BITS 64
DEFAULT REL

%include "../include/syscalls.inc"

global _start
global sys_write
global sys_strlen
global sys_exit

section .text

sys_write:
    ; Purpose:
    ;       Outputs data; IO function
    ;
    ; Arguments:
    ;       rdi -> fd to write to
    ;       rsi -> buffer to write
    ;       rdx -> length of buffer
    ;
    ; Returns:
    ;       rax -> number of bytes
    ;              written

    mov rax, SYS_write
    syscall

    ret


sys_exit:
    ; Purpose:
    ;       exits
    ;
    ; Arguments:
    ;       rdi -> exit code
    ;
    ; Returns:
    ;       None

    mov rax, SYS_exit
    syscall

    ud2

sys_strlen:
    ; Purpose:
    ;       Outputs data
    ;
    ; Arguments:
    ;       rdi -> string to measure
    ;
    ; Returns:
    ;       rax -> length of string
    
    xor rax, rax

    compute:
        
        cmp byte [rdi+rax], 0
        je str_done

        inc rax
        jmp compute

    str_done:
        
        ret

