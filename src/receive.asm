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

section .rodata

    received_stuff              db "Received"
    received_stuff_len          equ $ - received_stuff
    received_stuff2             db "somethin"

    reception_response_len      equ 256
    reception_guard             equ reception_response_len - 32

    reception_buffer_len        equ 2250

section .bss
    reception_buffer            resb reception_buffer_len       ; 45 bytes * 50 frequencies
    reception_response          resb reception_response_len     ; +RCV=<Address>,<Length>,<Data>,<RSSI>,<SNR>\r\n
    rec_CRC_tag                 resb CRC_len
    rec_CRC_tag_hex             resb CRC_len * 2
    data_length                 resq 1

section .text
    
    extern int_to_ascii
    extern write_loop                   
    extern SIGout
    extern append_CRLF
    extern termios_config
    extern config_module
    extern SIGrypt_CRC_Validate
    extern destroy_block
    extern hex_to_bytes
    global SIGrypt_receive


is_SIGrypt_format:

    ; Purpose:
    ;       checks to see if buffer is
    ;       in SIGrypt-valid format
    ;
    ; Args:
    ;       rdi -> buffer to check
    ;       rsi -> size of buffer
    ;   
    ; Returns:
    ;       rax ->  0 on success
    ;       rax -> -1 on failure

    push rbx
    push r12
    push r13

    test rsi, rsi
    jz check_hex_success

    mov r12, rdi
    lea r13, [rdi + rsi - 1]

    check_hex_format:

        mov al, byte [r13]

        cmp al, '-'
        je post_hex_check

        cmp al, '0'
        jb check_hex_failed

        cmp al, ':'
        jb post_hex_check

        cmp al, 'A'
        jb check_hex_failed

        cmp al, 'F'
        ja check_hex_failed

        post_hex_check:

            cmp r12, r13
            je check_hex_success

            dec r13

            jmp check_hex_format
            

    check_hex_failed:

        mov rax, -1
        jmp check_hex_terminate
        
        
    check_hex_success:
        
        xor rax, rax

    check_hex_terminate:
        
        pop r13
        pop r12
        pop rbx

        ret
    

strip_padding:

    ; Purpose:
    ;       Removes trailing 'P's in-place
    ;       for a buffer
    ;
    ; Args:
    ;       rdi -> buffer to strip
    ;       rsi -> size of buffer
    ;   
    ; Returns:
    ;       rax -> length on success
    ;       rax -> -1 on failure

    push r12

    lea rdx, [rdi + rsi - 1]

    strip_padding_loop:

        mov al, byte [rdx]

        cmp al, 'P'
        jne strip_padding_success

        mov byte [rdx], 0

        dec rdx
        
        cmp rdx, rdi
        jg strip_padding_loop
        
    strip_padding_failed:

        mov rax, -1
        jmp strip_padding_terminate
    
    strip_padding_success:

        sub rdx, rdi
        inc rdx

        mov rax, rdx
  
    strip_padding_terminate:

        pop r12
        ret


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
    ; r14 not touched, it contains module_FD
    push r15
    
    mov r12, rdi
    mov r13, rsi
    lea r15, [reception_buffer]
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

        ; Protects against buffer overflows

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


        lea rsi, [reception_response]
        lea rdi, [reception_response+reception_response_len]
        xor rcx, rcx

        find_data:

            ; Finds the received data, located 2 commas after +RCV

            mov al, byte [rsi]
            cmp al, ','
            sete dl
            
            movzx edx, dl
            add rcx, rdx

            inc rsi
            cmp rsi, rdi
            jge listening_failed

            cmp rcx, 2
            jne find_data


        lea rdi, [r15]
        mov rcx, 45
        rep movsb

        add r15, 45

        mov rdi, 10
        mov rsi, 1
        
        call SIGout

        xor rbx, rbx

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

        write_no_read:

            mov rax, SYS_write
            mov rdi, r14
            lea rsi, [frequency_buffer+rbx]
            mov rdx, [frequency_buffer_len]
            sub rdx, rbx
            syscall

            add rbx, rax
            cmp rbx, [frequency_buffer_len]
            jne write_no_read

        xor rbx, rbx

        inc rbp
        cmp rbp, FREQ_COUNT
        jl loop_LoRa

    xor rax, rax
    jmp listening_done

    listening_failed:
        mov rax, -1

    listening_done:

        pop r15
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
    ;       rax ->  0 on success
    ;   
    ;       rax -> 1 on block destruction failure
    ;       rax -> 2 on strip-padding failure
    ;       rax -> 3 on config failure
    ;       rax -> 4 on write failure
    ;       rax -> 5 on non SIGrypt format
    ;       rax -> 6 on data block alloc failure
    ;       rax -> 7 on reception failure
    ;       rax -> 8 on malock failure
    ;       rax -> 9 on hex_to_bytes failure
    ;       rax -> 10 on CRC validation failure

    push rbx
    push rbp
    push r12
    push r13
    push r14

    mov r13, rsi
    mov r14, rdi                        ; write_loop expects module_FD in r14

    call termios_config

    test rax, rax
    js rec_config_failed

    mov rdi, r13
    mov rsi, r14

    call config_module

    test rax, rax
    js rec_config_failed

    lea rdi, [cmd_Address_R]
    mov rsi, cmd_Address_R_len

    call write_loop

    test rax, rax
    jnz rec_write_failed

    mov rdi, r14
    mov rsi, r13

    call listen_LoRa

    test rax, rax
    jnz reception_failed
    
    lea rdi, [reception_buffer]
    mov rsi, reception_buffer_len

    call strip_padding    

    test rax, rax
    js rec_strip_failed

    mov qword [data_length], rax

    lea rdi, [reception_buffer]
    mov rsi, reception_buffer_len

    call SIGout

    lea rdi, [reception_buffer]
    mov rsi, [data_length]

    call is_SIGrypt_format

    test rax, rax
    js SIGrypt_format_invalid

    mov rax, SYS_mmap
    mov rdi, 0
    mov rsi, block_size
    mov rdx, 1 | 2
    mov r10, 2 | 0x20
    mov r8, -1
    mov r9,  0
    syscall

    test rax, rax
    js rec_data_block_alloc_failed

    mov r12, rax

    mov rax, SYS_mlock
    lea rdi, [r12]
    mov rsi, block_size
    syscall

    js rec_mlock_failed

    mov rax, [data_length]
    sub rax, CRC_len * 2                    ; rax now is length at CRC tag
    lea rsi, [reception_buffer]
    add rsi, rax
    lea rdi, [rec_CRC_tag_hex]
    mov rcx, CRC_len * 2
    rep movsb

    lea rdi, [rec_CRC_tag_hex]
    mov rsi, CRC_len * 2
    lea rdx, [rec_CRC_tag]
    
    call hex_to_bytes

    test rax, rax
    js rec_hex2bytes_failed

    lea rdi, [reception_buffer]
    mov rsi, [data_length]
    sub rsi, CRC_len * 2
    lea rdx, [rec_CRC_tag]

    ; in CRC errors, negative address for rax, and possible off by one for rec_CRC_tag

    call SIGrypt_CRC_Validate

    jnz rec_CRC_validation_failed
  
rec_destroy_A:

    mov rax, SYS_munlock
    lea rdi, [r12]
    mov rsi, block_size
    syscall 

    lea rdi, [r12]
    mov rsi, block_size

    call destroy_block

    jnz rec_destruction_failure

    ; if recv has at 45 bytes, jump to the next frequency

reception_success:
   
    xor rax, rax

terminate_reception:

    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    ret

rec_destruction_failure:

    mov rax, 1
    jmp terminate_reception

rec_strip_failed:

    mov rax, 2
    jmp terminate_reception

rec_config_failed:

    mov rax, 3
    jmp terminate_reception

rec_write_failed:
    
    mov rax, 4
    jmp terminate_reception

SIGrypt_format_invalid:

    mov rax, 5
    jmp terminate_reception

rec_data_block_alloc_failed:

    mov rax, 6
    jmp terminate_reception

reception_failed:

    mov rax, 7
    jmp terminate_reception

rec_mlock_failed:

    mov rax, 8
    jmp terminate_reception

rec_hex2bytes_failed:
    
    mov rax, 9
    jmp terminate_reception

rec_CRC_validation_failed:

    mov rax, 10
    jmp terminate_reception
