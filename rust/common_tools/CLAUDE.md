# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`common_tools` is a **Tauri v2 desktop application** (productName "ByteBench") exposing developer utilities — network byte-order conversion, raw-packet hex analysis + PCAP export, multi-protocol PCAP traffic generation (TCP/HTTP/ICMP/UDP/FTP/SSH/MySQL, optional VLAN), regex matching, MD5 hashing, and `\000`↔`\u0000` string-escape conversion. The UI is the original HTML/CSS/JS frontend; an **axum** web server runs *inside the same process* (bound to `127.0.0.1` on a random free port) and the Tauri WebView window points at it, so the frontend's `fetch('/api/...')` calls work unchanged. All frontend assets are embedded into the binary at compile time (`include_str!`), so the executable is self-contained.

The Rust crate lives in **`src-tauri/`** (conventional Tauri layout); the frontend is at the project-root **`static/`**. There is one **local path-dependency sub-crate, `genpcap/`** — the PCAP-generation core ported from the sibling `rust/gen_pcap` project (see "PCAP generation" below); otherwise no Cargo workspace. Other sibling dirs under `rust/` (`tls_ja4`, …) are unrelated.

## Layout

```
common_tools/
├── static/                     # frontend (the redesigned "Signal" UI) = Tauri frontendDist
├── genpcap/                    # local path-dep sub-crate: PCAP-generation core (ported from rust/gen_pcap)
│   ├── Cargo.toml              #   deps: pnet_packet + pnet_base + rand (pure Rust, NO libpcap/pnet_datalink)
│   └── src/{lib.rs, conversation.rs, l4.rs, flows.rs, core/, tcp/, http/, session/, vlan/}   # pure packet-byte gen (IPv4/IPv6, MTU seg/frag), no IO/license/yaml
├── src-tauri/
│   ├── Cargo.toml              # the crate; `tauri` is an OPTIONAL dep behind the `desktop` feature; genpcap = path "../genpcap"
│   ├── build.rs                # calls tauri_build::build() ONLY when CARGO_FEATURE_DESKTOP is set
│   ├── tauri.conf.json         # productName ByteBench, identifier com.bytebench.commontools, bundle=nsis
│   ├── capabilities/default.json
│   ├── icons/                  # icon.ico used for Windows build (generated with ImageMagick)
│   └── src/{main.rs, server.rs, web_api.rs, network_utils.rs, packet_analyzer.rs, pcap_generator.rs, regex_matcher.rs, md5_utils.rs, string_converter.rs}
├── BUILD_WINDOWS.md            # how to build the Windows desktop app
└── README.md / DEPLOYMENT.md   # OLD web-server docs (stale — predate the Tauri/redesign work)
```

## Commands

All cargo commands run from **`src-tauri/`**.

```bash
# --- Desktop (Tauri) build: only works where a WebView runtime + (on Win) MSVC exist ---
cargo build --release            # portable exe (default features = desktop)
cargo tauri build                # installer via NSIS (needs `cargo install tauri-cli`)
cargo tauri dev                  # dev window with reload

# --- Server-only build: NO Tauri dep — use this to verify all app logic anywhere (incl. this Linux box) ---
cargo build --no-default-features
CT_PORT=3031 ./target/debug/common_tools     # runs the embedded server headless; open http://127.0.0.1:3031

# --- Tests (inline #[cfg(test)] only in md5_utils.rs and string_converter.rs) ---
cargo test --no-default-features                                          # all tests, no Tauri
cargo test --no-default-features string_converter::tests::test_round_trip_conversion   # one test
```

**Tauri v2 cannot be built on this Linux host** (Ubuntu 20.04 only ships webkit2gtk-4.0; Tauri v2 needs 4.1) and **cannot be cross-compiled to Windows from Linux** — build the desktop app on Windows (see `BUILD_WINDOWS.md`). The `--no-default-features` server build is the cross-platform way to compile/run/verify everything except the Tauri shell.

## Architecture

- **`src-tauri/src/main.rs`** — two entry points selected by the `desktop` Cargo feature:
  - *desktop* (default): spawns the axum server on a background Tokio runtime bound to `127.0.0.1:0`, sends the chosen port back over an `mpsc` channel, then opens a `tauri::WebviewWindow` (`WebviewUrl::External`) at `http://127.0.0.1:<port>`.
  - *server* (`--no-default-features`): a plain `#[tokio::main]` axum server (port from `CT_PORT` env, else auto). No Tauri symbols compiled.
- **`src-tauri/src/server.rs`** — `create_router()` (all routes) + the page/static handlers + the `include_str!`-embedded assets. Framework-agnostic; shared by both entry points.
- **`src-tauri/src/web_api.rs`** — all `/api/*` handlers, the request/response DTOs, the uniform `ApiResponse<T> { success, data, error, timestamp }` envelope, and the `create_*_routes()` functions. Each handler builds a fresh utility struct and wraps the result in `ApiResponse`.
- **Feature modules** (`network_utils`, `packet_analyzer`, `pcap_generator`, `regex_matcher`, `md5_utils`, `string_converter`) — pure logic, no axum/tauri deps. HTTP concerns stay in `web_api.rs`, pure logic stays here.

**State model:** there is no shared/cross-request state. Every request constructs a new utility instance; `StringConverter`'s internal cache never persists (new instance per request).

### PCAP generation (`genpcap` sub-crate + `pcap_generator.rs`)

The `genpcap/` path-dep crate is a **trimmed port of `rust/gen_pcap`**: only the pure packet-byte generation (`core`/`tcp`/`http`/`session`/`vlan`) — the original's `license`, `template`/YAML, CLI, file IO, and the native **`pcap` (libpcap)** dependency were all dropped. It depends on **`pnet_packet` + `pnet_base`** (NOT the umbrella `pnet`, which pulls `pnet_datalink` → needs npcap SDK on Windows and would break the self-contained build) + `rand`. Re-porting: copy those module dirs, `rm vlan/packet.rs` (unused, not in `vlan/mod.rs`), and `sed 's/pnet::packet::/pnet_packet::/; s/pnet::util::MacAddr/pnet_base::MacAddr/'`.

`pcap_generator.rs` is the common_tools-side wrapper: it builds a `genpcap::TcpSessionConfig` from request params, calls `generate_sessions()` → `session.generate_packets(&flow)`, applies VLAN, and serializes the `Vec<Vec<u8>>` frames to **in-memory PCAP bytes via `pcap_file`** (same crate `packet_analyzer` uses — no libpcap). The `/generate` handler streams those bytes back as a `generated.pcap` attachment with `x-session-count`/`x-packet-count`/`x-flow` headers; `/save` instead writes them to disk via `save_pcap()` (output dir defaults to `std::env::current_dir()`, auto-created; filename defaults to `generated_<timestamp>.pcap`, only the basename of a user-supplied name is used) and returns JSON with the resolved `filename`/`path`.

**Protocols / flows** (`genpcap::flows` + `ApplicationFlowType`): `Tcp(TcpMode)` (SynOnly / Handshake / HandshakeClose=4-way / HandshakeReset=RST), `Http(HttpConfig)` (default GET-per-URI, or verbatim `request_content`/`response_content`), `Icmp`/`Udp`, `Ftp(FtpMode)` (active/passive: control + data channels), `Ssh`, `Mysql`. **IPv4 and IPv6** are both supported (version comes from the IP range; src/dst must match — `pcap_generator` rejects mixed). TCP-based flows are built by **`conversation::TcpConversation`** (tracks client/server seq, computes ack at send time → Wireshark-clean streams, and splits payloads by MSS); ICMP/UDP frames come from **`l4.rs`** (hand-built IPv4/IPv6 + checksums; ICMPv6 for v6). **`GenOptions { mtu, payload_size }`** is threaded through `ApplicationFlow::generate_packets`: oversize payloads are **TCP-segmented** (MSS = MTU − IP − TCP) or **IP-fragmented** (UDP/ICMP — IPv4 frag flags / IPv6 fragment ext-header), and `payload_size` auto-fills filler content when the user supplies none. App-protocol payloads (FTP/SSH/MySQL) are **representative**, not full state machines. The selected protocol is the request's `protocol` field; `pcapgen.html` shows per-protocol option panels.

### Adding a new tool

1. `src-tauri/src/<tool>.rs` with the pure logic.
2. `mod <tool>;` in `main.rs`.
3. In `web_api.rs`: request/response structs, an `async fn` handler returning `Json(ApiResponse::success(...))`, and `pub fn create_<tool>_routes() -> Router`.
4. In `server.rs`: `.nest("/<tool>", web_api::create_<tool>_routes())` inside `api_routes()`; add the tool to `api_info()`'s endpoint list.
5. Add `static/<tool>.html`, embed it in `server.rs` (`const <TOOL>_HTML = include_str!("../../static/<tool>.html")`), add its `/`-level route + a `/static/*` match arm, and a nav link in the other HTML pages.

## Endpoints

`GET /health`, `GET /api` (info) · `POST /api/network/convert` · `POST /api/packet/{analyze,export,download}` · `POST /api/pcap/{generate,save}` (generate → `.pcap` attachment download; save → writes the `.pcap` to a server-side directory, default = process CWD, returns JSON `{filename,path,...}`) · `POST /api/regex/match` · `POST /api/md5/{calculate,calculate_file}` · `POST /api/string/convert`. Pages: `/`, `/network.html`, `/packet.html`, `/pcapgen.html`, `/regex.html`, `/md5.html`, `/string.html`; embedded assets under `/static/*`.

## Gotchas

- **`build.rs` must guard `tauri_build::build()`** behind `CARGO_FEATURE_DESKTOP` — `tauri-build` panics ("missing `cargo:dev` instruction") if run when the `tauri` crate isn't compiled (i.e. the `--no-default-features` server build). Keep that guard.
- **Frontend is embedded at compile time** (`include_str!` with paths relative to `src-tauri/src/`, e.g. `../../static/index.html`). The runtime no longer reads `static/` from disk, so the binary is location-independent — but if you add/rename a static file you must update the embeds in `server.rs`.
- **`README.md` / `DEPLOYMENT.md` are stale** — they describe the pre-Tauri web server (and even say "Warp", which was never accurate; it was axum, now embedded in Tauri). Trust this file + `BUILD_WINDOWS.md`.
- **`POST /api/packet/export` writes `packet.pcap` into the process CWD.** For an in-memory download use `POST /api/packet/download` (returns the PCAP bytes as an attachment) — that's what the frontend uses.
- **All user-facing strings and comments are in Chinese**; match that convention. The frontend uses Google Fonts (Chakra Petch / IBM Plex) with system fallbacks, so it renders fine offline.
- Packet analysis (`packet_analyzer.rs`) is a hand-rolled fixed-offset parser for Ethernet → IPv4 → TCP/UDP/ICMP; no VLAN tags, no IP options beyond header-length, no IPv6.
