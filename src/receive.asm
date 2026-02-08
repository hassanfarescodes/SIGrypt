; ==========================================
; File: receive.asm
; Author: Hassan Fares
;
; Description:  Handles module receptions
;
; Assembler: NASM
; Architecture: x86-64
; ==========================================

BITS 64
DEFAULT REL

%include "../include/syscalls.inc"
%include "../include/data_block.inc"
%include "../include/frequency_variations.inc"
%include "../include/behaviour_config.inc"

; ================================================================================
;                               Ciphertext (hex) format
; --------------------------------------------------------------------------------
; AES Encrypted Ciphtertext || IV || - || time seconds || HMAC tag || CRC checksum
; --------------------------------------------------------------------------------
; Size:      2048              32    2         16            96           16
;
; Total max size: 2210 bytes 
; ================================================================================


extern frequency_buffer
extern frequency_buffer_len

section .rodata:

    received_stuff              db "Received"
    received_stuff_len          equ $ - received_stuff
    received_stuff2             db "somethin"

    reception_response_len      equ 256
    reception_guard             equ reception_response_len - 32

section .bss

    reception_buffer            resb 2250                       ; 45 bytes * 50 frequencies
    reception_response          resb reception_response_len     ; +RCV=<Address>,<Length>,<Data>,<RSSI>,<SNR>\r\n

section .text
    
    extern int_to_ascii
    extern write_loop                       
    extern SIGout
    extern append_CRLF
    extern termios_config
    extern config_module
    global SIGrypt_receive


listen_LoRa:

    ; Purpose:
    ;       Checks response of TTY
    ;       "+RCV" means it received
    ;
    ; Args:
    ;       rdi -> module FD
    ;       rsi -> frequency table address
    ;   
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push rbx
    push rbp
    push r12
    push r13
    push r14

    mov r12, rdi
    mov r13, rsi
    xor rbp, rbp

    lea rdi, [reception_prompt]
    mov rsi, reception_prompt_len
    
    call SIGout

    reset_offset:
    
        xor rbx, rbx

    loop_LoRa:

        mov rax, SYS_read
        mov rdi, r12
        lea rsi, [reception_response + rbx]
        mov rdx, 32
        syscall

        test rax, rax
        js listening_failed
        jz loop_LoRa
        
        add rbx, rax

        ; Protects against overflows

        cmp rbx, reception_guard
        jge reset_offset

        cmp byte [reception_response + rbx - 1], 10
        jne loop_LoRa

        lea rdi, [reception_response]
        mov rsi, rbx

        call SIGout

        xor rbx, rbx

        cmp dword [reception_response], 0X5643522B                  ; == "+RCV" ?
        jne loop_LoRa

        ;lea rdi, [received_stuff]
        ;mov rsi, received_stuff_len
        ;call SIGout

        mov rdi, 10
        mov rsi, 1
        
        call SIGout

        xor rbx, rbx

        ;lea rdi, [received_stuff2]
        ;mov rsi, received_stuff_len

        ;call SIGout

        mov edi, dword [r13 + rbp * 4 + 4]
        lea rsi, [frequency_buffer + cmd_Band_len]
    
        call int_to_ascii

        test rax, rax
        js listening_failed

        mov [frequency_buffer_len], rax
        add qword [frequency_buffer_len], cmd_Band_len

        lea rdi, [frequency_buffer]
        add rdi, qword [frequency_buffer_len]
        
        call append_CRLF

        add qword [frequency_buffer_len], 2

        lea rdi, [frequency_buffer]
        mov rsi, [frequency_buffer_len]

        call write_loop

        test rax, rax
        jnz listening_failed

        ;lea rdi, [frequency_buffer]
        ;mov rsi, [frequency_buffer_len]

        ;call SIGout

        inc rbp
        cmp rbp, FREQ_COUNT
        jl loop_LoRa

    xor rax, rax
    jmp listening_done

    listening_failed:
        mov rax, -1

    listening_done:

        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx

        ret

SIGrypt_receive:

    ; Purpose:
    ;       Recieves encrypted payloads
    ;       with user-defined params
    ;
    ; Args:
    ;       rdi -> module FD
    ;       rsi -> frequency table address
    ;   
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push rbx
    push rbp
    push r12
    push r13
    push r14

    mov r12, rdi
    mov r13, rsi

    mov r14, r12                                    ; write_loop expects module_FD in r14


    call termios_config

    test rax, rax
    js reception_failed

    mov rdi, r13
    mov rsi, r12

    call config_module

    test rax, rax
    js reception_failed

    lea rdi, [cmd_Address_R]
    mov rsi, cmd_Address_R_len

    call write_loop

    test rax, rax
    jnz reception_failed

    mov rdi, r12
    mov rsi, r13

    call listen_LoRa

    test rax, rax
    jnz reception_failed

    jmp reception_success

    ; if recv has at 45 bytes, jump to the next frequency
    

reception_failed:

    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    
    mov rax, -1
    ret


reception_success:
    
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    xor rax, rax
    ret
