#[derive(Debug)]
struct ListNode {
    value: i32,
    next: Option<Box<ListNode>>,
}

impl ListNode {
    // 创建一个新的链表节点
    fn new(value: i32) -> Self {
        ListNode {
            value,
            next: None,
        }
    }

    // 在链表末尾添加一个新节点
    // &mut self：表示该方法需要对调用者的可变借用。这意味着在调用 append 方法时，链表的当前节点必须是可变的。
    // value: i32：表示要添加到链表中的新节点的值。
    fn append(&mut self, value: i32) {
        // self.next 是一个 Option<Box<ListNode>> 类型，表示当前节点的下一个节点。
        // 如果 self.next 是 Some，表示当前节点有下一个节点。ref mut 关键字用于获取 next_node 的可变引用。
        if let Some(ref mut next_node) = self.next {
            //如果当前节点有下一个节点，则递归地调用 append 方法在下一个节点上。这将遍历链表直到找到最后一个节点。
            next_node.append(value);
        } else {    //如果当前节点没有下一个节点（即 self.next 是 None），则创建一个新节点并将其设置为当前节点的下一个节点。
            let new_node = Box::new(ListNode::new(value));  //创建一个新的链表节点，并将其包装在 Box 中，以便在堆上分配内存。
            self.next = Some(new_node); //将新创建的节点设置为当前节点的下一个节点。
        }
    }

    // 修改链表中某个位置的值
    fn update(&mut self, index: usize, value: i32) -> bool {
        if index == 0 {
            self.value = value;
            true
        } else {
            match self.next.as_mut() {
                Some(next_node) => next_node.update(index - 1, value),
                None => false,
            }
        }
    }
}

fn main() {
    // 创建一个链表
    let mut head = ListNode::new(1);
    head.append(2);
    head.append(3);

    // 修改链表中某个位置的值
    head.update(1, 10);

    // 打印链表
    println!("{:?}", head);
}