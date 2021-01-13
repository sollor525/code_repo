/*
attribute是GNU C特色之一，系统中有许多地方使用到。attribute可以设置函数属性（Function Attribute ）、变量属性（Variable Attribute ）和类型属性（Type Attribute)等。

函数属性(Function Attribute):
noreturn
noinline
always_inline
pure
const
nothrow
sentinel
format
format_arg
no_instrument_function
section
constructor
destructor
used
unused
deprecated
weak
malloc
alias
warn_unused_result
nonnull

类型属性(Type Attributes)：
aligned
packed
transparent_union,
unused,
deprecated
may_alias

变量属性(Variable Attribute)：
aligned
packed

Clang特有的：
availability
overloadable

书写格式：
attribute后面会紧跟一对原括弧，括弧里面是相应的attribute参数:
__attribute__(xxx)
*/