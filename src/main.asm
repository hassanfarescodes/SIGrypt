; ==========================================
; File: main.asm
; Author: Hassan Fares
;
; Description:  Main file / Starter 
;
; Assembler: NASM
; Architecture: x86-64
; ==========================================

%include "../include/syscalls.inc"

section .text

    extern START_SIGrypt
    global _start


_start:

    push rbp
    push r12
    push r13
    push r14
    push r15
    push rbx

    call START_SIGrypt

    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp

    mov rdi, rax
    mov rax, SYS_exit
    syscall
