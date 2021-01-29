.intel_syntax noprefix
.text
    .globl _start
_start:
mov    rax, 1
mov    rbx, 2
add    rax, rbx
cmp    rdi, 0x5
ja     foo
mov    eax, edi
lea    rdx, [rax*4+0x0]
lea    rax, [.jt]
add    rax,rdx
jmp    rax
.L1:
add    rbx, 2
ret
.L2:
mov    rax, 1
ret
.L3:
imul   rax, rdx
ret
.L4:
mov    rcx, rax
add    rbx, rcx
ret
foo:
add    rbx, 1
mov    rcx, rbx
ret

.section .rodata
.jt:
.quad .L1
.quad .L2
.quad .L3
.quad .L4
