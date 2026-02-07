; ==========================================
; File: detect_entries.asm
; Author: Hassan Fares
;
; Description:  Detects & displays USB 
;               RF modules
;
; Assembler: NASM
; Architecture: x86-64
; ==========================================

BITS 64

DEFAULT REL

%include "../include/syscalls.inc"

section .bss

    entry_buf resb 8192
    mod_num   resb 8
    remaining resb 8

section .rodata

    path        db "/dev", 0              ; USB-to-serial RF modules path
    is_module   db "ttyUSB"
    newline     db 10
    reset       db 27, "[0m"
    reset_len equ $ - reset
    detected_p  db 10, 10, "Detected Serial Modules: ", 10, "------------------------", 10, 10, 27, "[92m"
    detected_p_len equ $ - detected_p

    USB_num_p   db 9, 9, 27, "[93m", "(USB Number: "
    USB_num_p_len equ $ - USB_num_p

    close_par   db ")", 27, "[92m"
    close_par_len equ $ - close_par

    no_detected db 27, "[91m", "Could not find any serial modules!", 10, 10, 27, "[0m"
    no_detected_len equ $ - no_detected

section .text
    extern SIGout
    global detect_entries

detect_entries:

    push rbx
    push r12
    push r13
    push r14
    push r15

    lea rdi, [detected_p]
    mov rsi, detected_p_len
    
    call SIGout

    mov rax, SYS_openat
    mov rdi, -100
    lea rsi, [path]
    xor rdx, rdx
    xor r10, r10
    syscall

    mov r12, rax
    xor r15, r15

read_entries:
    
    mov rax, SYS_getdents64
    mov rdi, r12
    lea rsi, [entry_buf]
    mov rdx, 8192
    syscall
    
    test rax, rax
    jz no_more_entries

    mov [remaining], rax
    lea r13, [entry_buf]
    
next:
    
    cmp qword [remaining], 0
    jle read_entries

    movzx r14d, word [r13+16]   ; d_reclen by getdents64
    lea rsi, [r13+19]
    lea rdi, [is_module]

    xor rdx, rdx
    xor r8, r8
    lea rcx, [mod_num]

detect_module:
       
    mov al, byte [rdi+rdx]
    cmp byte [rsi+rdx], al
    jne skip_entry

    cmp rdx, 5              ; len("ttyUSB") offset for pointer
    je find_length

    inc rdx
    jmp detect_module

find_length:
    inc rdx

    mov al, byte [rsi+rdx]
    mov byte [rcx+r8], al

    inc r8

    cmp byte [rsi+rdx], 0
    jne find_length

print_entry:

    inc r15
    
    mov rbx, r8

    lea rdi, [rsi]
    mov rsi, rdx

    call SIGout

    lea rdi, [USB_num_p]
    mov rsi, USB_num_p_len

    call SIGout

    lea rdi, [mod_num]
    mov rsi, rbx

    call SIGout

    lea rdi, [close_par]
    mov rsi, close_par_len

    call SIGout

    lea rdi, [newline]
    mov rsi, 1
    
    call SIGout

skip_entry:
    add r13, r14
    sub qword [remaining], r14
    jmp next

no_more_entries:
    
    test r15, r15
    jnz terminate

    lea rdi, [no_detected]
    mov rsi, no_detected_len

    call SIGout

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp

    mov rax, -1
    ret
    

terminate:
    lea rdi, [reset]
    mov rsi, reset_len

    call SIGout

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx

    xor rax, rax
    ret
