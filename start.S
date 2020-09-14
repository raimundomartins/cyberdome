.global _start
_start:
    xor %ebp, %ebp;
    mov %rdx, %r9;
    pop %rdi;
    mov %rsp, %rsi;
    and $~16, %rsp;
    lea 8(%rsi, %rdi, 8), %rdx;
    push    %rax;
    push    %rsp;
    push    %rdx;
    call main;
    movq %rax,%rdi;
    movl $60,%eax;
    syscall;
    int3;
