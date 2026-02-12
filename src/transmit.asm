; ==========================================
; File: transmit.asm
; Author: Hassan Fares
;
; Description:  Handles module transmissions 
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


global frequency_buffer
global frequency_buffer_len
global response_buffer

section .bss
    transmission_buffer         resb 2304       ; 45 bytes * 50 frequencies = 2250 max payload size
                                                ; Rounded up to nearest multiple 256 to accomadate CMDs
    send_command_buffer         resb 128
    termios_block               resb 60
    frequency_buffer            resb 32
    response_buffer             resb 32
    frequency_buffer_len        resq 1

section .text
    extern int_to_ascii
    extern SIGout
    global write_loop
    global config_module
    global termios_config
    global append_CRLF
    global SIGrypt_transmit


termios_config:

    ; Purpose:
    ;       Configure serial communication
    ;       with the module
    ;
    ; Args:
    ;       rdi -> module FD
    ;   
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push r14

    mov r14, rdi

    mov rax, SYS_ioctl
    mov rdi, r14
    mov rsi, 0X5401
    lea rdx, [termios_block]
    syscall

    test rax, rax
    js termios_ioctl_failed

    mov dword [termios_block], 0                ; c_iflag = 0   (Disable input processing)
    mov dword [termios_block + 4], 0            ; c_oflag = 0   (Disable output processing)

    mov eax, dword [termios_block + 8]          ; load c_cflag

    and eax, ~(0X0100 | 0X0040 | 0X80000000)    ; 0X0100 turns parity off
                                                ; 0X0040 sets 1 stop bit
                                                ; 0X80000000 turns RTS/CTS control off

    and eax, ~0X0030                            ; clear CSIZE bits (character size)

    and eax, ~0x0000100F
    or eax, 0x00001002

    or eax, (0X0800 | 0X0080 | 0X0030)          ; 0X0030 sets character size to 8 data bits
                                                ; 0X0080 enables receiver
                                                ; 0X0030 ignores modem control lines

    mov dword [termios_block + 8], eax

    mov dword [termios_block + 12], 0           ; c_lflag = 0   (Disable canonical mode)

    mov byte [termios_block + 23], 0            ; VMIN
    mov byte [termios_block + 22], 1            ; VTIME (0.1 second read wait)

    mov dword [termios_block + 52], 0X1002      ; BAUD = 115200
    mov dword [termios_block + 56], 0X1002      ; BAUD = 115200

    mov rax, SYS_ioctl
    mov rdi, r14
    mov rsi, 0X5402
    lea rdx, [termios_block]
    syscall
    
    pop r14

    test rax, rax
    js termios_config_failed

    xor rax, rax
    ret

termios_ioctl_failed:
    pop r14

    mov rax, -2
    ret

termios_config_failed:

    mov rax, -1
    ret

config_module:

    ; Purpose:
    ;       Configures PARAMETER, NETWORKID, BAND, CRFOP
    ;
    ; Args:
    ;       rdi -> frequency table address
    ;       rsi -> module_FD
    ;   
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push rbx
    push r14
    push r15

    mov r14, rsi                            ; write_loop expects module_FD to be in r14
    lea r15, [rdi]


    lea rdi, [configuration_prompt]
    mov rsi, configuration_prompt_len

    call SIGout

    xor rbx, rbx

    lea rdi, [cmd_Spreading_factor]
    mov rsi, cmd_Spreading_factor_len

    call write_loop

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [cmd_Network_ID]
    mov rsi, cmd_Network_ID_len

    call write_loop

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [cmd_Receive]
    mov rsi, cmd_Receive_len

    call write_loop

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [cmd_Output_power]
    mov rsi, cmd_Output_power_len

    call write_loop
    
    test rax, rax
    cmovne rbx, [error_val]

    lea rsi, [cmd_Band]
    lea rdi, [frequency_buffer]
    mov rcx, cmd_Band_len
    rep movsb
    
    mov edi, dword [r15]
    lea rsi, [frequency_buffer]
    add rsi, cmd_Band_len
    
    call int_to_ascii

    test rax, rax
    cmovs rbx, [error_val]

    mov [frequency_buffer_len], rax

    lea rdi, [frequency_buffer + cmd_Band_len + rax]
    call append_CRLF

    lea rdi, [frequency_buffer]
    mov rsi, [frequency_buffer_len]                            
    add rsi, cmd_Band_len + 2                   ; +2 for "\r\n"
    call write_loop                             ; Writes the initial frequency

    test rax, rax
    cmovne rbx, [error_val]

    mov rax, rbx

    pop r15
    pop r14
    pop rbx

    ret

check_response:

    ; Purpose:
    ;       Checks response of TTY
    ;       "+OK" means it succeeded
    ;
    ; Args:
    ;       rdi -> module FD
    ;       rsi -> number of reads
    ;   
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push rbx

    mov rbx, rsi
    
    xor eax, eax

    keep_reading:

    dec rbx
    js not_found

    mov rax, SYS_read
    lea rsi, [response_buffer]
    mov rdx, 32
    syscall
    
    test rax, rax
    js not_found
    jz keep_reading                             ; TTY timed out (VTIME limit)

    lea rsi, [response_buffer]
    mov r8, rax

    scan_ok:

        shl eax, 8                              ; Insert new 0 byte at the end
        mov al, [rsi]                           ; Insert response character
        inc rsi
        dec r8

        mov edx, eax
        and edx, 0x0000FFFF
        cmp dx, 0x4F4B                          ; rax == "OK" ?
        je found

        test r8, r8
        jnz scan_ok
        jmp keep_reading
                
    found:
    
        pop rbx

        xor rax, rax
        ret

    not_found:
        
        pop rbx

        mov rax, -1
        ret

write_loop:

    ; Purpose:
    ;       Writes to the module and returns
    ;       response code
    ;
    ; Args:
    ;       rdi -> Content buffer address
    ;       rsi -> buffer length
    ;       Expects module_FD to be in r14
    ;   
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push rbx
    push r12
    push r13
    xor rbx, rbx

    lea r12, [rdi]
    mov r13, rsi

    write_module:

        mov rax, SYS_write
        mov rdi, r14
        lea rsi, [r12 + rbx]
        mov rdx, r13
        sub rdx, rbx
        syscall

        test rax, rax
        js write_failed

        add rbx, rax

        cmp rbx, r13 
        jne write_module

        mov rdi, r14
        mov rsi, 4                          ; 0.1 * 4 = 0.4 seconds dwell time limit
                                            ; Waits for +OK to be read from serial
        call check_response                 ; Terminates if +OK is not detected in 0.4 seconds

        pop r13
        pop r12
        pop rbx  
    
        ret

    write_failed:

        pop r13
        pop r12
        pop rbx  
        
        mov rax, -1
    
        ret


append_CRLF:

    ; Purpose:
    ;       Appends "\r\n" to buffer
    ;
    ; Args:
    ;       rdi -> end of buffer
    ;   
    ; Returns:
    ;       None

    mov word [rdi], 0x0A0D

    ret

SIGrypt_transmit:

    ; Purpose:
    ;       Transmits encrypted payloads
    ;       with user-defined params
    ;
    ; Args:
    ;       rdi -> ciphertext payload
    ;       rsi -> ciphertext length
    ;       rdx -> module FD
    ;       rcx -> frequency table address
    ;   
    ; Returns:
    ;       rax -> 0 on success
    ;
    ;       rax -> 50 on ioctl
    ;       rax -> 51 on module write
    ;       rax -> 52 on termios config
    ;       rax -> 53 on module config
    ;       rax -> 54 on general transmissions
    ;       rax -> 55 on int_to_ascii

    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    sub rsp, 8                                  ; Pad for stack alignment

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx                                ; write_loop expects module_FD to be in r14
    mov r15, rcx

    mov rdi, r14

    call termios_config

    test rax, rax
    js trans_termios_config_failed

    lea rdi, [r15]
    mov rsi, r14

    call config_module

    test rax, rax
    js trans_config_module_failed

    lea rdi, [cmd_Address_T]
    mov rsi, cmd_Address_T_len
    
    call write_loop
    
    test rax, rax
    jnz trans_write_failed



start_transmissions:

    lea rsi, [cmd_Send]
    lea rdi, [transmission_buffer]
    mov rcx, cmd_Send_len

    rep movsb

    lea rsi, [arg_Dest_addr]
    lea rdi, [transmission_buffer]
    add rdi, cmd_Send_len
    mov rcx, arg_Dest_addr_len

    rep movsb

    lea rsi, [arg_Payload_length]
    lea rdi, [transmission_buffer]
    add rdi, cmd_Send_len
    add rdi, arg_Dest_addr_len
    mov rcx, arg_Payload_length_len

    rep movsb

    lea rdi, [transmission_buffer]
    add rdi, cmd_Send_len
    add rdi, arg_Dest_addr_len
    add rdi, arg_Payload_length_len

    lea rbx, [rdi]
   
    ; Now transmission_buffer is "AT+SEND=7775,45,"

    mov al, byte [padding]
    mov rcx, 2304 - cmd_Send_len - arg_Dest_addr_len - arg_Payload_length_len

    rep stosb

    lea rsi, [r12]
    lea rdi, [rbx]
    mov rcx, r13
    rep movsb

    xor rbp, rbp

    cmp r13, 45*FREQ_COUNT
    ja  trans_transmissions_failed
    
    lea rdi, [transmission_prompt]
    mov rsi, transmission_prompt_len
    call SIGout

    
    transmission_loop:
        
        ; Segment data into 50 pieces (1 piece per frequency)

        lea rdi, [rbx]
        mov rsi, rdi
        imul rax, rbp, 45
        add rsi, rax
        mov rcx, 45
        rep movsb

        ; Transmit Data

        lea rsi, [transmission_buffer]
        lea rdi, [send_command_buffer]
        mov rcx, cmd_Send_len + arg_Dest_addr_len + arg_Payload_length_len + 45
        rep movsb

        call append_CRLF

        lea rdi, [send_command_buffer]
        mov rsi, cmd_Send_len + arg_Dest_addr_len + arg_Payload_length_len + 45 + 2

        call write_loop

        ; Wait 20 ms

        mov rax, SYS_nanosleep
        lea rdi, [time_sleep]
        xor rsi, rsi
        syscall

        ; Frequency hop

        mov edi, dword [r15 + rbp * 4 + 4]
        lea rsi, [frequency_buffer + cmd_Band_len]
    
        call int_to_ascii

        test rax, rax
        js trans_int2ascii_failed

        mov [frequency_buffer_len], rax
        add qword [frequency_buffer_len], cmd_Band_len

        lea rdi, [frequency_buffer]
        add rdi, qword [frequency_buffer_len]
        
        call append_CRLF

        add qword [frequency_buffer_len], 2

        lea rdi, [frequency_buffer]
        mov rsi, [frequency_buffer_len]

        call write_loop 

        inc rbp
        cmp rbp, FREQ_COUNT                     ; "FREQ_COUNT" in
                                                ; ../include/frequency_variations.inc

        jge transmission_succeeded
        jmp transmission_loop

    
transmission_succeeded:

    xor rax, rax

transmission_terminate:

    mov rbx, rax

    mov rax, SYS_close
    mov rdi, r14
    syscall

    mov rax, rbx

    add rsp, 8

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    ret

trans_ioctl_failed:

    mov rax, 50
    jmp transmission_terminate

trans_write_failed:

    mov rax, 51
    jmp transmission_terminate

trans_termios_config_failed:

    cmp rax, -2
    je trans_ioctl_failed

    mov rax, 52
    jmp transmission_terminate

trans_config_module_failed:

    mov rax, 53
    jmp transmission_terminate

trans_transmissions_failed:

    mov rax, 54
    jmp transmission_terminate

trans_int2ascii_failed:

    mov rax, 55
    jmp transmission_terminate
