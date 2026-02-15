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
; Size:      2048              32    1         16            96           16
;
; Total max size: 2209 bytes 
; ================================================================================

extern frequency_buffer
extern frequency_buffer_len

section .rodata

    open_sb                     db 27, "[1m", "[ "
    open_sb_len                 equ $ - open_sb

    close_sb                    db " ]", 27, "[0m"
    close_sb_len                equ $ - close_sb

    time_AM                     db " AM"
    time_AM_len                 equ $ - time_AM

    time_PM                     db " PM"
    time_PM_len                 equ $ - time_PM

    time_universal_zone         db " - UTC"
    time_universal_zone_len     equ $ - time_universal_zone

    time_format_seperator       db " : "
    time_format_seperator_len   equ $ - time_format_seperator

    reception_response_len      equ 256
    reception_guard             equ reception_response_len - 32

    reception_buffer_len        equ 2250

section .data

    rec_progress_bar:           db 13, '['
                                times 50 db ' '
                                db ']'

    rec_progress_bar_len        equ $ - rec_progress_bar

section .bss

    reception_buffer            resb reception_buffer_len       ; 45 bytes * 50 frequencies
    reception_response          resb reception_response_len     ; +RCV=<Address>,<Length>,<Data>,<RSSI>,<SNR>\r\n
    sa_int                      resb 32
    rec_CRC_tag_hex             resb CRC_len * 2
    rec_CRC_tag                 resb CRC_len
    old_message_ID_1            resb IV_len
    old_message_ID_2            resb IV_len
    old_message_tracker         resq 1
    cipher_IV_length            resq 1
    data_length                 resq 1
    format_time_hours           resq 1
    format_time_minutes         resq 1
    format_time_seconds         resq 1
    format_time_hours_len       resq 1
    format_time_minutes_len     resq 1
    format_time_seconds_len     resq 1
    packets_received            resq 1
    PM_flag                     resb 1
    quit_flag                   resb 1

section .text
    
    extern int_to_ascii
    extern ascii_to_int
    extern write_loop                   
    extern SIGout
    extern append_CRLF
    extern termios_config
    extern config_module
    extern SIGrypt_CRC_Validate
    extern hmac_validate
    extern destroy_block
    extern hex_to_bytes
    extern DECRYPT_AES
    global SIGrypt_receive

sigreturn_stub:
    mov rax, SYS_rt_sigreturn
    syscall
    ud2

sigint_handler:

    mov byte [rel quit_flag], 1
    ret

install_signals:

    lea rax, [rel sigint_handler]
    mov [sa_int], rax
    mov qword [sa_int + 8], 0X10000000 | 0X04000000 
    lea rax, [sigreturn_stub]
    mov qword [sa_int + 16], rax
    mov qword [sa_int + 24], 0

    mov rax, SYS_rt_sigaction
    mov rdi, 2
    lea rsi, [sa_int]
    xor rdx, rdx
    mov r10, 8
    syscall

    ret

reset_progress_bar:
    
    lea rdi, [rec_progress_bar + 2]
    mov rcx, 50
    mov al, byte ' '
    rep stosb

    mov qword [packets_received], 0

    ret

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
    mov qword [packets_received], 0

    lea rdi, [reception_prompt]
    mov rsi, reception_prompt_len
    
    call SIGout

    lea rdi, [newline]
    mov rsi, 1
        
    call SIGout

    reset_offset:
    
        xor rbx, rbx

    loop_LoRa:

        cmp byte [rel quit_flag], 1
        je listening_aborted

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
        ja reset_offset

        cmp byte [reception_response + rbx - 1], 10
        jne loop_LoRa

        cmp dword [reception_response], 0X5643522B                  ; == "+RCV" ?
        jne reset_offset
        
        lea rax, [rec_progress_bar + 2]
        mov rdx, [packets_received]

        mov byte [rax+rdx], '#'

        lea rdi, [rec_progress_bar]
        mov rsi, rec_progress_bar_len
      
        call SIGout
        
        inc qword [packets_received]


        ; lea rdi, [reception_response]                             ; Uncomment to see serial receptions
        ; mov rsi, rbx

        ; call SIGout

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

        ; lea rdi, [newline]                                            ; Aids in serial debug visualization, prints \n
        ; mov rsi, 1
        
        ; call SIGout

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
      
            test rax, rax
            jle listening_failed

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
        jmp listening_done

    listening_aborted:
        mov rax, -2

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
    ;       rax -> 6 on SIGout failure
    ;       rax -> 7 on reception failure
    ;       rax -> 8 on int_to_ascii failure
    ;       rax -> 9 on hex_to_bytes failure
    ;       rax -> 10 on CRC validation failure
    ;       rax -> 11 on hmac validation failure
    ;       rax -> 12 on absent encrypted data
    ;       rax -> 13 on decryption failure
    ;       rax -> 14 on timestamp validation failure
    ;       rax -> 15 on signal installation failure
    ;       rax -> 16 on message ID validation

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

    lea rdi, [clear_terminal]
    mov rsi, clear_terminal_len

    call SIGout
    
    call install_signals                        ; Not RF, this is a keyboardinterrupt handler

    test rax, rax
    jnz rec_signal_installation_failed
    
    reception_logic_loop:

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

        cmp rax, -2
        je reception_success 

        test rax, rax
        jnz reception_failed

        lea rdi, [newline]
        mov rsi, 1
        
        call SIGout

        call reset_progress_bar
        
        lea rdi, [reception_buffer]
        mov rsi, reception_buffer_len

        call strip_padding    

        test rax, rax
        js rec_strip_failed

        mov qword [data_length], rax

        lea rdi, [reception_buffer]
        mov rsi, [data_length]

        call is_SIGrypt_format

        test rax, rax
        js SIGrypt_format_invalid

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

        call SIGrypt_CRC_Validate

        test rax, rax
        jnz rec_CRC_validation_failed

        lea rsi, [reception_buffer]
        add rsi, [data_length]
        sub rsi, (CRC_len * 2 + HMAC_len * 2)
        lea rdi, [HMAC_hex]
        mov rcx, HMAC_len * 2
        rep movsb

        lea rdi, [HMAC_hex]
        mov rsi, HMAC_len * 2
        lea rdx, [HMAC]
        
        call hex_to_bytes

        test rax, rax
        js rec_hex2bytes_failed

        lea rdi, [reception_buffer]
        mov rsi, [data_length]
        sub rsi, (CRC_len * 2 + HMAC_len * 2)
        lea rdx, [HMAC_key]
        mov rcx, HMAC_len
        lea r8, [HMAC]

        call hmac_validate

        test rax, rax
        jnz rec_HMAC_validation_failed
            

        lea rdi, [reception_buffer]
        lea rsi, [reception_buffer]
        add rsi, [data_length]

    find_encrypted_data:

        mov al, byte [rdi]

        cmp rdi, rsi
        je rec_absent_encrypted_failure

        inc rdi
    
        cmp al, '-'
        jne find_encrypted_data
        
    found_encrypted_data:

        ; General callee-saved registers safe to use past this point: rbx, r15

        lea rbx, [rdi]              ; In this line, rbx and rdi point to payload transmission timestamp

    rec_validate_timestamp:

        mov rax, [data_length]      ; Length(timestamp) = End Address of Data - Start address of timestamp - HMAC length - CRC length
        lea rsi, [reception_buffer + rax]

        sub rsi, rdi 
        sub rsi, (HMAC_len * 2 + CRC_len * 2)

        lea rdi, [rbx]
        ; rsi is already calculated above

        call ascii_to_int

        mov r15, rax

        mov rax, SYS_time
        xor rdi, rdi
        syscall

        sub rax, r15                    ; Calculates delay (Includes propagation, transmission, and processing delay)
  
        test rax, rax
        js rec_validate_timestamp_failed

        cmp rax, 30
        jg rec_validate_timestamp_failed 

        add r15, rax                    ; r15 now holds current time (Transmission time + Reception Delay = Current time)

    post_timestamp_validation:

        lea rsi, [reception_buffer]
        sub rbx, rsi                    ; Calculates the length of the encrypted data along with IV
        dec rbx                         ; Accomadates for loop structure (inc rdi)

        mov [cipher_IV_length], rbx

        mov rdi, qword [cipher_IV_length]
        sub rdi, IV_len * 2
        shr rdi, 1

        mov qword [plaintext_len], rdi

        lea rdi, [reception_buffer]
        mov rsi, [cipher_IV_length]
        sub rsi, IV_len * 2
        lea rdx, [ciphertext]

        call hex_to_bytes

        test rax, rax
        js rec_hex2bytes_failed

        lea rdi, [reception_buffer]
        mov rsi, [cipher_IV_length]
        sub rsi, IV_len * 2
        add rdi, rsi
        mov rsi, IV_len * 2
        lea rdx, [IV]

        call hex_to_bytes

        test rax, rax
        js rec_hex2bytes_failed

        mov rax, [IV]
        mov rdx, [IV + 8]

    compare_ID_1:

        cmp rax, [old_message_ID_1]
        jne compare_ID_2
      
        cmp rdx, [old_message_ID_1 + 8]
        je rec_ID_validation_failed

    compare_ID_2:

        cmp rax, [old_message_ID_2]
        jne post_ID_validation
      
        cmp rdx, [old_message_ID_2 + 8]
        je rec_ID_validation_failed

    post_ID_validation:

        inc qword [old_message_tracker]
  
        test qword [old_message_tracker], 1
        jz rec_ID_2_write 

        rec_ID_1_write:

            lea rsi, [IV]
            lea rdi, [old_message_ID_1]
            mov rcx, IV_len
            rep movsb
            jmp post_message_ID_validation
    
        rec_ID_2_write:

            lea rsi, [IV]
            lea rdi, [old_message_ID_2]
            mov rcx, IV_len
            rep movsb

        post_message_ID_validation:

            lea rdi, [r12]

            call DECRYPT_AES

            test rax, rax
            jnz rec_decryption_failed

    format_current_time:

        ; Seconds

        mov rax, r15
        xor rdx, rdx
        mov rcx, 60
        div rcx

        mov r15, rax

        mov rdi, rdx
        lea rsi, [format_time_seconds]

        call int_to_ascii

        test rax, rax
        js rec_int2ascii_failed

        mov [format_time_seconds_len], rax

        ; Minutes

        mov rax, r15
        xor rdx, rdx
        mov rcx, 60
        div rcx

        mov r15, rax

        mov rdi, rdx
        lea rsi, [format_time_minutes]

        call int_to_ascii
        
        test rax, rax
        js rec_int2ascii_failed 
        
        mov [format_time_minutes_len], rax

        mov byte [PM_flag], 0

        ; Hours

        mov rax, r15
        xor rdx, rdx
        mov rcx, 24
        div rcx

        cmp rdx, 12
        setae byte [PM_flag]

        ; Convert military time to 12-hour time
       
        ; 12-hour time = ((military_time + 11) % 12) + 1     UTC

    military_time_conversion:

        add rdx, 11
      
        mov rax, rdx
        xor rdx, rdx
        mov rcx, 12
        div rcx

        add rdx, 1

        mov rdi, rdx
        lea rsi, [format_time_hours]

        call int_to_ascii

        test rax, rax
        js rec_int2ascii_failed

        mov [format_time_hours_len], rax

        lea rdi, [newline]
        mov rsi, 1
      
        call SIGout

        lea rdi, [open_sb]
        mov rsi, open_sb_len

        call SIGout

        lea rdi, [format_time_hours]
        mov rsi, [format_time_hours_len]

        call SIGout

        lea rdi, [time_format_seperator]
        mov rsi, time_format_seperator_len

        call SIGout

        lea rdi, [format_time_minutes]
        mov rsi, [format_time_minutes_len]

        call SIGout

        lea rdi, [time_format_seperator]
        mov rsi, time_format_seperator_len

        call SIGout
    
        lea rdi, [format_time_seconds]
        mov rsi, [format_time_seconds_len]

        call SIGout

        cmp byte [PM_flag], 1
        je set_PM

        set_AM:

            lea rdi, [time_AM]
            mov rsi, time_AM_len

            call SIGout

            jmp end_time_format

        set_PM:

            lea rdi, [time_PM]
            mov rsi, time_PM_len

            call SIGout

    end_time_format:

        lea rdi, [close_sb]
        mov rsi, close_sb_len

        call SIGout

        lea rdi, [time_universal_zone]
        mov rsi, time_universal_zone_len
        
        call SIGout
      
    display_validated_content:

        lea rdi, [rec_message_prompt]
        mov rsi, rec_message_prompt_len

        call SIGout

        test rax, rax
        jnz rec_SIGout_failed

        lea rdi, [decrypted]
        mov rsi, [plaintext_len]

        call SIGout

        test rax, rax
        jnz rec_SIGout_failed

        lea rdi, [newline]
        mov rsi, 1
        
        call SIGout
      
        test rax, rax
        jnz rec_SIGout_failed

        jmp reception_logic_loop

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

rec_SIGout_failed:

    mov rax, 6
    jmp terminate_reception

reception_failed:

    mov rax, 7
    jmp terminate_reception

rec_int2ascii_failed:

    mov rax, 8
    jmp terminate_reception

rec_hex2bytes_failed:
    
    mov rax, 9
    jmp terminate_reception

rec_CRC_validation_failed:

    mov rax, 10
    jmp terminate_reception

rec_HMAC_validation_failed:
    
    mov rax, 11
    jmp terminate_reception

rec_absent_encrypted_failure:

    mov rax, 12
    jmp terminate_reception

rec_decryption_failed:
    
    mov rax, 13
    jmp terminate_reception

rec_validate_timestamp_failed:

    mov rax, 14
    jmp terminate_reception

rec_signal_installation_failed:

    mov rax, 15
    jmp terminate_reception

rec_ID_validation_failed:

    mov rax, 16
    jmp terminate_reception
