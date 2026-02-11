; ==========================================
; File: main.asm
; Author: Hassan Fares
;
; Description:  Handles user experience 
;               and memory security
;
; Assembler: NASM
; Architecture: x86-64
; ==========================================

BITS 64
DEFAULT REL

%include "../include/syscalls.inc"      ; Defined syscall names to number mapping

%include "../include/data_block.inc"    ; See "Data Block Memory Layout" below for
                                        ; more details!

; =================================================================
;           !   NOTE: FREQUENCIES ARE BASED IN THE US   !
; =================================================================

%include "../include/frequency_variations.inc"

;   Data Block Memory Layout (3696 bytes): 
;
;   Name            Base    Start   End     Size
;   ============================================
;   ciphertext      r12     0       1023    1024
;   decrypted       r12     1024    2047    1024
;   plaintext       r12     2048    3071    1024
;   roundkeys       r12     3072    3311    240
;   HMAC_hex        r12     3312    3439    128
;   HMAC            r12     3440    3487    48
;   HMAC_key        r12     3488    3535    48
;   AES_key         r12     3536    3583    48
;   IV_hex          r12     3584    3615    32
;   CRC_tag_hex     r12     3616    3631    16
;   IV              r12     3632    3647    16
;   IV_copy         r12     3648    3663    16
;   key_schedule    r12     3664    3679    16
;   plaintext_len   r12     3680    3687    8
;   CRC_tag         r12     3688    3695    8
;
;   CONSTANT: block_size = 4096  (2 pages worth)

section .rodata

    USB_prompt      db 10, "Enter the USB number to use (in Detected Serial Modules) : "
    USB_prompt_len  equ $ - USB_prompt

    USB_error       db 10, 10, "ERROR: No such USB number!", 10, 10, "Example: If you want to use ttyUSB3, you should enter 3", 10, 10
    USB_error_len   equ $ - USB_error

    Key_prompt      db 10, "Enter 24 word key : "
    Key_pro_len     equ $ - Key_prompt

    Freq_prompt     db 10, "Enter frequency table number (1-20) : "
    Freq_prompt_len equ $ - Freq_prompt

    Crit_prompt     db 10, "Please enter exactly 24 words for the key!", 10
    Crit_prompt_len equ $ - Crit_prompt

    Tip_prompt      db 10, "Tip: Tired of typing your inputs? Go to /misc for info to automate this process!", 10
    Tip_prompt_len  equ $ - Tip_prompt

    Mes_prompt      db 10, "Enter message : "
    Mes_pro_len     equ $ - Mes_prompt

    data_sep        db "-"
    data_sep_len    equ $ - data_sep

    Freq_error      db 10, "Enter a number between 1 and 20 inclusive!", 10, 10
    Freq_error_len  equ $ - Freq_error

    AES_label       db " enc", 0
    HMAC_label      db " mac", 0
    label_len       equ $ - HMAC_label
    
    newline         db 10
    
    hex_symbols     db "0123456789ABCDEF"
    
    key_path        db "../include/key_words.txt", 0

    error_A         db 10, "[!] CRITICAL: FAILED TO WIPE MEMORY BLOCK A!", 10
    error_B         db 10, "[!] CRITICAL: FAILED TO WIPE MEMORY BLOCK B!", 10

    error_len       equ $ - error_B

    error_init      db 10, "[!] CRITICAL: FAILED TO WIPE KEY INITILIZATION BLOCK!", 10
    error_init_len  equ $ - error_init

    error_wipes     db 10, "[!] CRITICAL FAILED TO WIPE SIGRYPT BUFFERS!", 10
    error_wipes_len equ $ - error_wipes

    CRC_len         equ 8

    IV_len          equ 16

    AES_len         equ 48
    HMAC_len        equ 48


section .data

    rlim_core_zero:
                    dq 0    ; rlim_cur
                    dq 0    ; rlim_max

    module_name     db "/dev/ttyUSB", 0
                    times 10 db 0
  
ascii_art:
    db 0x1b, '[5m', 10
    db "                                                  *", 10
    db "                                                    *", 10
    db "                                          *           *", 10
    db "                                            *          *", 0x1b, '[0m', 10
    db "              .- -.  ", 0x1b, '[5m', "            *           *         *", 0x1b, '[0m', 10
    db "             /\     \      ", 0x1b, '[5m', "        *         *        *  ", 0x1b, '[0m', 10
    db "            /  \     \__...-.O ", 0x1b, '[5m', "    *        *        *", 0x1b, '[0m', 10
    db "           |     .    \   .'' ", 0x1b, '[5m', "    *        *        *", 0x1b, '[0m', 10
    db "           |      \    \.'  '  ", 0x1b, '[5m', "  *        *        *", 0x1b, '[0m', 10
    db "            \      \   /   '                     ", 10
    db "             \       ./   /  ", 10
    db "              |        \ / \", 10
    db "              ||'        \  \", 10
    db "              ||  ` . . ..' '", 10
    db "              ||", 10
    db "             |  |  ", 10
    db "          _-'|  |'- _", 10
    db "        /     ||     \\", 10
    db "       /      ||      \\", 10
    db "      //      ||       \\           By: Hassan Fares", 10
    db "   __//_______||________\\__        Version: 1.0", 10
    db "   \________SIGRYPT________/        ", 10, 10, 10
    db "[0] Generate a key",10
    db "[1] Transmit a message", 10
    db "[2] Receive a message", 10
    db "[3] Exit", 10, 10
    db "Enter option (0 to 3) : "

ascii_art_len: equ $ - ascii_art

section .bss
    ciphertext_hex      resb    3072 
    initial_key         resb    256     ; max(len(word)) * 24 = 9 * 24
    master_key          resb    256
    master_AES_key      resb    256     ; SHA256(master_key || " enc")
    master_HMAC_key     resb    256     ; SHA256(master_key || " mac")
    fstat_buf           resb    144
    IV_cache            resb    64
    prompt              resb    16
    time_buffer         resb    16
    time_buffer_len     resb    8
    USB_num             resb    8
    frequency_ptr       resq    1
    Freq_num            resq    1
    master_key_len      resq    1
    module_FD           resq    1

section .text

    extern ENCRYPT_AES
    extern zero_fill
    extern hmac_sha384
    extern sha384
    extern sys_strlen
    extern detect_entries
    extern SIGrypt_CRC_ECMA182
    extern SIGrypt_receive
    extern SIGrypt_transmit
    global destroy_block
    global int_to_ascii
    global SIGout
    global _start


SIGrypt_wipe_sensitive:

    push rbx

    xor rbx, rbx

    lea rdi, [plaintext]
    mov rsi, 1024

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [HMAC_key]
    mov rsi, HMAC_len

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [AES_key]
    mov rsi, AES_len

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [roundkeys]
    mov rsi, 240

    call zero_fill
    
    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [key_schedule]
    mov rsi, 16

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    mov rax, rbx

    pop rbx

    ret 
    
    

SIGrypt_mlock_masters:

    ; Purpose:
    ;       mlocks master key buffers
    ;
    ; Args:
    ;       None
    ;   
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push rbx

    xor rbx, rbx

    mov rax, SYS_mlock
    lea rdi, [master_key]
    mov rsi, 256
    syscall

    test rax, rax
    cmovne rbx, [error_val]

    mov rax, SYS_mlock
    lea rdi, [master_HMAC_key]
    mov rsi, 256
    syscall

    test rax, rax
    cmovne rbx, [error_val]

    mov rax, SYS_mlock
    lea rdi, [master_AES_key]
    mov rsi, 256
    syscall

    test rax, rax
    cmovne rbx, [error_val]

    mov rax, SYS_mlock
    lea rdi, [master_key_len]
    mov rsi, 8
    syscall

    test rax, rax
    cmovne rbx, [error_val]

    mov rax, rbx

    pop rbx

    ret


SIGrypt_munlock_masters:

    ; Purpose:
    ;       mlocks master key buffers
    ;
    ; Args:
    ;       None
    ;   
    ; Returns:
    ;       None
    
    push rbx

    mov rax, SYS_munlock
    lea rdi, [master_key]
    mov rsi, 256
    syscall

    mov rax, SYS_munlock
    lea rdi, [master_HMAC_key]
    mov rsi, 256
    syscall

    mov rax, SYS_munlock
    lea rdi, [master_AES_key]
    mov rsi, 256
    syscall

    mov rax, SYS_munlock
    lea rdi, [master_key_len]
    mov rsi, 8
    syscall

    pop rbx

    ret


destroy_block:

    ; Purpose:
    ;       Wipes, unlocks, and unmaps 
    ;       the memory block used
    ;
    ; Args:
    ;       rdi -> start address of memory block
    ;       rsi -> size of memory block
    ;
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push rbx
    push r12
    push r13

    xor rbx, rbx

    mov r12, rdi
    mov r13, rsi

    cld

    xor rax, rax
    mov rdi, r12
    mov rcx, r13
    rep stosb

    mov rax, SYS_munlock
    mov rdi, r12
    mov rsi, r13
    syscall

    test rax, rax
    cmovne rbx, [error_val]

    mov rax, SYS_munmap
    mov rdi, r12
    mov rsi, r13
    syscall

    test rax, rax
    cmovne rbx, [error_val]


    destroy_done:
        
        mov rax, rbx

        pop r13
        pop r12
        pop rbx

        ret


SIGrypt_wipe_buffers:

    ; Purpose:
    ;       Wipes sensitive SIGrypt buffers
    ;
    ; Args:
    ;       None
    ;
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push rbx
    xor rbx, rbx

    lea rdi, [ciphertext_hex]
    mov rsi, 3072

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [master_AES_key]
    mov rsi, 256

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [master_HMAC_key]
    mov rsi, 256

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [IV_cache]
    mov rsi, 64

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [time_buffer]
    mov rsi, 16

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [time_buffer_len]
    mov rsi, 8

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [frequency_ptr]
    mov rsi, 8

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [Freq_num]
    mov rsi, 8

    call zero_fill

    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [master_key]
    mov rsi, 256

    call zero_fill
    
    test rax, rax
    cmovne rbx, [error_val]

    lea rdi, [master_key_len]
    mov rsi, 8

    call zero_fill
    
    test rax, rax
    cmovne rbx, [error_val]

    mov rax, rbx

    pop rbx

    ret


SIGout:
    ; Purpose:
    ;       Prints using write syscall
    ;
    ; Args:
    ;       rdi -> address of buffer
    ;       rsi -> length of buffer
    ;
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> 1 on failure
    push rbx

    mov r8, rdi
    mov rbx, rsi

    mov rax, SYS_write
    mov rdi, 1
    mov rsi, r8
    mov rdx, rbx
    syscall
   
    cmp rax, rbx
    setne al
    movzx rax, al

    pop rbx

    ret


SIGin:
    ; Purpose:
    ;       Inputs using read syscall
    ;
    ; Args:
    ;       rdi -> address of read buffer
    ;       rsi -> length of read buffer
    ;
    ; Returns:
    ;       rax -> num of bytes read

    mov r8, rdi
    mov r9, rsi

    mov rax, SYS_read
    mov rdi, 0
    mov rsi, r8
    mov rdx, r9
    syscall

    ret


string_strip:
    ; Purpose:
    ;       Strips string of leading and
    ;       trailing whitespace(s) + newline(s)
    ;
    ; Args:
    ;       rdi -> address of buffer
    ;       rsi -> length of buffer
    ;       rdx -> address of dest buffer
    ;
    ; Returns:
    ;       rax -> length on success
    ;       rax -> -1 on failure

    mov r8, rdi
    mov r9, rsi
    add r9, rdi

    check_start:

        mov al, byte [rdi]
        inc rdi

        cmp rdi, r9
        jg strip_failed

        cmp al, 32
        je check_start

        dec rdi                 ; Accomadate loop structure 
        mov r10, rdi            ; Address of the start of whitespace-free

        mov rdi, r9
        dec rdi                 ; Accomadate true end of buffer

    check_end:

        cmp rdi, r10
        jl strip_failed
        
        mov al, byte [rdi]
        dec rdi

        cmp al, 10
        je check_end

        cmp al, 32
        je check_end

        inc rdi                 ; Accomadate loop structure
        mov r11, rdi            ; Address of the end of whitespace-free


    strip_logic: 
        
        lea rsi, [r10]
        lea rdi, [rdx]

        sub r11, r10
        mov rcx, r11
        inc rcx
        
        mov r8, rcx             ; Save to return in rax

        rep movsb
    

    mov rax, r8
    ret

    strip_failed:
      
        mov rax, -1
        ret


count_spaces:
    ; Purpose:
    ;       Returns number of spaces of a buffer
    ;
    ; Args:
    ;       rdi -> address of buffer
    ;       rsi -> size of buffer
    ;
    ; Returns:
    ;       rax -> number as int

    xor rax, rax
    mov r8, -1

    count_spaces_loop:

        inc r8

        cmp r8, rsi
        jge count_spaces_done

        cmp byte [rdi+r8], 32
        jne count_spaces_loop
        
        inc rax

        jmp count_spaces_loop
        
    count_spaces_done:
        ret
    

ascii_to_int:

    ; Purpose:
    ;       Returns int type of ascii positive number input
    ;
    ; Args:
    ;       rdi -> address of ascii number buffer
    ;       rsi -> size of ascii number buffer
    ;
    ; Returns:
    ;       rax -> number as int

    xor r8, r8
    xor rax, rax

    int_cast_loop:

        mov cl, byte [rdi+r8]

        sub cl, '0'

        cmp cl, 9
        ja casted_int

        cmp r8, rsi
        jge casted_int

        movzx rcx, cl

        imul rax, rax, 10
        
        add rax, rcx

        inc r8

        jmp int_cast_loop

    casted_int:
        
        ret


int_to_ascii:

    ; Purpose:
    ;       Returns ascii type of int input
    ;
    ; Args:
    ;       rdi -> int to convert
    ;       rsi -> address to write ascii to 
    ;
    ; Returns:
    ;       rax -> ascii length on success
    ;       rax -> -1 on failure

    xor r8, r8
    mov rax, rdi
    mov rcx, 10

    ascii_cast_loop:
          
        xor rdx, rdx

        cmp rax, 0
        je casted_ascii

        div rcx

        add dl, '0'

        cmp dl, '0'
        jl casted_ascii_fail

        cmp dl, '9'
        jg casted_ascii_fail

        mov byte [rsi+r8], dl
        inc r8

        jmp ascii_cast_loop
        
    casted_ascii:

        lea rdi, [rsi]
        add rdi, r8
        dec rdi             ; accomadate for loop structure

        reverse_ascii_buffer:
        
            cmp rdi, rsi
            jbe casted_ascii_success
            
            mov al, byte [rdi]
            mov cl, byte [rsi]

            mov byte [rdi], cl
            mov byte [rsi], al

            inc rsi
            dec rdi

            jmp reverse_ascii_buffer

            
    casted_ascii_success:
        
        mov rax, r8
        ret

    casted_ascii_fail:
        
        mov rax, -1
        ret

SIGrypt_locate_frequency_variation:

    ; Purpose:
    ;       Computes the address of requested
    ;       frequency variation
    ;
    ; Args:
    ;       rdi -> requested frequency variation 
    ;       number
    ;
    ; Returns:
    ;       rax -> address of that frequency variation

    dec rdi ; number -> index

    lea rsi, [Frequency_Variations]
    mov rax, [rsi + rdi * 8]

    ret

secure_index:
    ; Purpose:
    ;       Returns crypto safe random
    ;       number for indexing the 
    ;       key word file
    ;
    ; Args:
    ;      None 
    ;
    ; Returns:
    ;       rax -> secure random number
    ;       between 0 and 7775

    push rbx    ; Stack Alignment Padding

    push rcx
    push rdx

    mov rcx, 7776 ; 0 to 7775 line index in /include/key_words.txt

    generate:

        rdrand rax
        jnc generate

        mul rcx

        cmp rax, 6208    ; (2 ^ 64) mod 7776 
        jb generate

    mov rax, rdx

    pop rdx
    pop rcx

    pop rbx

    ret

hex_to_bytes:

    ; Purpose:
    ;       Converts hex to bytes
    ;
    ; Args:
    ;       rdi -> Address of byte buffer
    ;       rsi -> Size of hex buffer
    ;       rdx -> Address of dest buffer
    ;
    ; Returns:
    ;       rax -> length of bytes on success
    ;       rax -> -1 on failure

    lea r10, [hex_symbols]
    xor r9, r9

    test rsi, rsi
    jz byte_conversion_end

    shr rsi, 1

    byte_conversion_loop:
        
        mov r11, -1

        mov al, byte [rdi]
        mov bl, byte [rdi+1]

        find_al:
            inc r11

            cmp r11, 15
            jg byte_conversion_failed

            cmp al, byte [r10+r11]
            jne find_al

        mov al, r11b
        shl al, 4
        
        mov r11, -1

        find_bl:
            inc r11

            cmp r11, 15
            jg byte_conversion_failed
            
            cmp bl, byte[r10+r11]
            jne find_bl

        mov bl, r11b
        and bl, 0x0F

        or al, bl

        mov byte [rdx], al

        inc r9
        inc rdx
        add rdi, 2

        cmp r9, rsi
        jl byte_conversion_loop
    
    byte_conversion_end:

        mov rax, r9
        ret
    
    byte_conversion_failed:
        mov rax, -1
        ret

bytes_to_hex:

    ; Purpose:
    ;       Converts bytes to hex
    ;
    ; Args:
    ;       rdi -> Address of byte buffer
    ;       rsi -> Size of byte buffer
    ;       rdx -> Address of dest buffer
    ;
    ; Returns:
    ;       rax -> hex length on success

    lea r10, [hex_symbols]
    xor r11, r11

    test rsi, rsi
    jz hex_conversion_end

    hex_conversion_loop:
    
        mov bl, byte [rdi]

        mov al, bl
        shr al, 4

        movzx eax, al

        mov cl, byte [r10 + rax]
        mov byte [rdx], cl
        
        inc rdx

        mov al, bl
        and al, 0x0F
        
        movzx eax, al

        mov cl, byte [r10 + rax]
        mov byte [rdx], cl

        inc rdx
        inc rdi
        inc r11

        cmp r11, rsi
        jl hex_conversion_loop

    hex_conversion_end:

        mov rax, r11
        shl rax, 1

        ret

SIGrypt_load_key_file:

    ; Purpose:
    ;       Creates and prints 24 word Sigrypt key
    ;
    ; Args:
    ;       None
    ;
    ; Returns:
    ;       rax -> (terminates) with 0 success code
    ;       rax -> (terminates) with 1 failure code


    push rbp
    
    mov rax, SYS_mlock
    lea rdi, [initial_key]
    mov rsi, 256
    syscall

    test rax, rax
    js failed

    mov rax, SYS_openat
    mov rdi, -100
    lea rsi, [key_path]
    mov rdx, 0
    xor r10, r10
    syscall

    test rax, rax
    js failed

    mov r15, rax

    mov rax, SYS_fstat
    mov rdi, r15
    lea rsi, [fstat_buf]
    syscall

    test rax, rax
    js failed

    ; mmap B

    mov rax, SYS_mmap
    xor rdi, rdi
    mov rsi, [fstat_buf + 48]
    mov rdx, 1
    mov r10, 2
    mov r8, r15
    xor r9, r9
    syscall
    
    test rax, rax
    js failed

    mov r14, rax

    mov rax, SYS_close
    mov rdi, r15
    syscall

    xor r11, r11
    lea r10, [initial_key]

    mov rdx, r10
    add rdx, 256                ; size of key_word buffer

    mov rcx, [fstat_buf + 48]
    add rcx, r14
    
    construct_master_key:

        mov rsi, r14
        
        xor r8, r8

        call secure_index
        mov r9, rax

        cmp r9, 0               ; edge case of index 0
        je edge_case_0

        loop_key_file:

            cmp byte [rsi], 10
            sete al
            movzx rax, al

            add r8, rax
            cmp r8, r9
            jne skip

            copy_word:
                
                inc rsi

            edge_case_0:

                cmp rsi, rcx
                jae failed_post_mmap_B

                cmp byte [rsi], 10
                je copy_done

                cmp r10, rdx
                jae failed_post_mmap_B

                mov al, byte [rsi]
                mov byte [r10], al
                inc r10

                jmp copy_word


            copy_done:
                
                inc r11

                cmp r11, 24
                je post_key_gen

                mov byte [r10], 32
                inc r10

                jmp construct_master_key


            skip:
                
                inc rsi
                cmp rsi, rcx
                jb loop_key_file


        post_key_gen:

            mov byte [r10], 10
            inc r10
            mov byte [r10], 0

            lea rdi, [initial_key]

            call sys_strlen

            mov r8, rax

            lea rdi, [initial_key]
            mov rsi, r8
          
            call SIGout
            
            test rax, rax
            jnz failed_post_mmap_B

            lea rdi, [initial_key]
            mov rsi, 256
            
            call zero_fill

            test rax, rax
            jnz failed_initial_key_wipe

            mov rax, SYS_munlock
            lea rdi, [initial_key]
            mov rsi, 256
            syscall

            destroy_B:

                mov rax, SYS_munmap
                mov rdi, r14
                mov rsi, [fstat_buf + 48]
                syscall

            pop rbp
            jmp terminate 


check_RDRAND:

    ; Purpose:
    ;       Checks to see if RDRAND is
    ;       supported on CPU
    ;
    ; Args:
    ;       None
    ;   
    ; Returns:
    ;       rax -> 1 on success
    ;       rax -> 0 on failure

    mov eax, 1
    cpuid
    bt ecx, 30
    setc al
    movzx rax, al

    ret


randomize:

    ; Purpose:
    ;       Fills a buffer with securely random bytes
    ;
    ; Args:
    ;       rdi -> Address of buffer
    ;       rsi ->    Size of buffer
    ;
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> 1 on failure

    mov r10, rdi
    mov r9, rsi

    xor r8, r8

    fill_loop:
        
        mov rax, SYS_getrandom
        lea rdi, [r10 + r8]
        mov rsi, r9
        sub rsi, r8
        xor rdx, rdx
        syscall

        test rax, rax
        js fill_fail

        add r8, rax
        cmp r8, r9
        jb fill_loop

        xor rax, rax

        ret

    fill_fail:
        mov rax, 1
        ret

_start:
    
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rbx

    ; Check if binary is getting ptraced

    mov rax, SYS_ptrace
    mov rdi, 0
    xor rsi, rsi
    xor rdx, rdx
    xor r10, r10
    syscall
  
    test rax, rax
    ;js failed                                      <-------- TODO: Remove after debugging

    ; Check if RDRAND is supported

    call check_RDRAND

    test rax, rax
    jz failed

    mov rax, SYS_setrlimit
    mov rdi, 4
    lea rsi, [rlim_core_zero]
    syscall
    
    test rax, rax
    js failed

    mov rax, SYS_prctl
    mov rdi, 4
    xor rsi, rsi
    xor rdx, rdx
    xor r10, r10
    xor r8, r8
    syscall

    test rax, rax
    js failed

    lea rdi, [ascii_art]
    mov rsi, ascii_art_len

    call SIGout

    lea rdi, [prompt]
    mov rsi, 16

    call SIGin

    lea rsi, [prompt]
    mov bl, byte [rsi]

    ; Generate key
    cmp bl, '0'
    je SIGrypt_load_key_file

    cmp bl, '3'
    je terminate

    ; Send a message
  
    call detect_entries

    test rax, rax
    jnz failed

    lea rdi, [USB_prompt]
    mov rsi, USB_prompt_len
    
    call SIGout

    lea rdi, [USB_num]
    mov rsi, 8
    
    call SIGin

    test rax, rax
    js failed

    lea rdi, [USB_num]
    mov rsi, rax
    lea rdx, [module_name + 11] ; +11 to skip /dev/ttyUSB

    call string_strip
  
    mov rax, SYS_openat
    mov rdi, -100
    lea rsi, [module_name]
    mov rdx, 2
    xor r10, r10
    syscall

    test rax, rax
    js no_such_module

    mov [module_FD], rax

    lea rdi, [Freq_prompt]
    mov rsi, Freq_prompt_len

    call SIGout

    lea rdi, [Freq_num]
    mov rsi, 4

    call SIGin

    test rax, rax
    js failed

    lea rdi, [Freq_num]
    mov rsi, 4
    
    call ascii_to_int

    test rax, rax
    js failed

    cmp rax, 20
    jg Frequency_error

    cmp rax, 1
    jl Frequency_error
  
    mov rdi, rax

    call SIGrypt_locate_frequency_variation

    mov qword [frequency_ptr], rax

    cmp bl, '1'
    je transmission_phase

reception_phase:

    mov rdi, [module_FD]
    mov rsi, [frequency_ptr]

    call SIGrypt_receive
    
    test rax, rax
    jnz failed

    jmp terminate
   

transmission_phase:  

    ; mmap A

    mov rax, SYS_mmap
    mov rdi, 0
    mov rsi, block_size
    mov rdx, 1 | 2
    mov r10, 2 | 0x20
    mov r8, -1
    mov r9,  0
    syscall

    test rax, rax
    js failed

    mov r12, rax

    mov rax, SYS_mlock
    mov rdi, r12
    mov rsi, block_size
    syscall
    
    test rax, rax
    js failed_post_mmap_A

    lea rdi, [Key_prompt]
    mov rsi, Key_pro_len
    
    call SIGout

    call SIGrypt_mlock_masters

    test rax, rax
    js failed_post_mmap_A

    lea rdi, [master_key]
    mov rsi, 256

    call SIGin

    test rax, rax
    js failed_post_mmap_A

    mov [master_key_len], rax

    lea rdi, [master_key]
    mov rsi, [master_key_len]
    
    call count_spaces

    cmp rax, 23
    jne key_input_failed

    lea rdi, [Mes_prompt]
    mov rsi, Mes_pro_len

    call SIGout

    lea rdi, [plaintext]
    mov rsi, 1024

    call SIGin

    test rax, rax
    jle failed_post_mmap_A

    mov qword [plaintext_len], rax

    ; remove '\n' if it exists
    cmp byte [plaintext+rax-1], 10
    sete al
    movzx eax, al
    sub qword [plaintext_len], rax

    lea rdi, [master_key]
    mov rsi, [master_key_len]
    lea rdx, [master_AES_key]

    call string_strip

    lea rsi, [AES_label]
    lea rdi, [master_AES_key]
    add rdi, rax
    mov rcx, label_len
    rep movsb

    lea rdi, [master_AES_key]
    mov rsi, rax
    add rsi, label_len
    lea rdx, [AES_key]

    call sha384

    test rax, rax
    jnz failed_post_mmap_A

    lea rdi, [master_key]
    mov rsi, [master_key_len]
    lea rdx, [master_HMAC_key]

    call string_strip

    lea rsi, [HMAC_label]
    lea rdi, [master_HMAC_key]
    add rdi, rax
    mov rcx, label_len
    rep movsb

    lea rdi, [master_HMAC_key]
    mov rsi, rax
    add rsi, label_len
    lea rdx, [HMAC_key]

    call sha384

    test rax, rax
    jnz failed_post_mmap_A


    lea rdi, [IV]
    mov rsi, IV_len
    
    call randomize

    test rax, rax
    jnz failed_post_mmap_A

    lea rdi, [r12]  
  
    ; Note: AES_key is 48 bytes, but ENCRYPT_AES
    ; will use the first 32 bytes of that key

    call ENCRYPT_AES

    test rax, rax
    jnz failed_post_mmap_A

    lea rdi, [IV]
    mov rsi, IV_len
    lea rdx, [IV_hex]
    
    call bytes_to_hex

    cmp rax, IV_len * 2
    jne failed_post_mmap_A

    lea rdi, [ciphertext]
    mov rsi, [plaintext_len]
    lea rdx, [ciphertext_hex]

    call bytes_to_hex

    cld

    lea rsi, [IV_hex]
    lea rdi, [ciphertext_hex]
    add rdi, [plaintext_len]
    add rdi, [plaintext_len]
    mov rcx, IV_len * 2
    rep movsb

    mov rax, SYS_time
    xor rdi, rdi
    syscall

    mov rdi, rax
    lea rsi, [time_buffer]

    call int_to_ascii

    mov [time_buffer_len], rax

    lea rsi, [data_sep]
    lea rdi, [ciphertext_hex]
    mov rdx, [plaintext_len]
    add rdx, IV_len
    shl rdx, 1
    add rdi, rdx
    mov rcx, data_sep_len
    rep movsb

    lea rsi, [time_buffer]
    lea rdi, [ciphertext_hex]
    mov rdx, [plaintext_len]
    add rdx, IV_len
    shl rdx, 1
    add rdx, data_sep_len
    add rdi, rdx
    mov rcx, [time_buffer_len]
    rep movsb

    lea rdi, [ciphertext_hex]
    mov rsi, [plaintext_len]
    add rsi, IV_len
    shl rsi, 1
    add rsi, data_sep_len
    add rsi, [time_buffer_len]
    lea rdx, [HMAC_key]
    mov rcx, HMAC_len
    lea r8, [HMAC]

    call hmac_sha384

    lea rdi, [HMAC]
    mov rsi, HMAC_len
    lea rdx, [HMAC_hex]

    call bytes_to_hex

    lea rsi, [HMAC_hex]
    lea rdi, [ciphertext_hex]
    mov rdx, [plaintext_len]
    add rdx, IV_len
    shl rdx, 1
    add rdx, [time_buffer_len]
    add rdx, data_sep_len
    add rdi, rdx
    mov rcx, HMAC_len * 2
    rep movsb

    lea rdi, [ciphertext_hex]
    mov rsi, [plaintext_len]
    add rsi, IV_len
    add rsi, HMAC_len
    shl rsi, 1
    add rsi, [time_buffer_len]
    add rsi, data_sep_len

    call SIGrypt_CRC_ECMA182

    lea rdi, [ciphertext_hex]
    mov rsi, [plaintext_len]
    add rsi, IV_len
    add rsi, HMAC_len
    shl rsi, 1
    add rsi, [time_buffer_len]
    add rsi, data_sep_len

    add rdi, rsi

    lea rdx, [rdi]
    lea rdi, [CRC_tag]
    mov rsi, CRC_len

    call bytes_to_hex

    lea rdi, [newline]
    mov rsi, 1
    call SIGout

    lea rdi, [CRC_tag_hex]
    mov rsi, CRC_len
    shl rsi, 1
    
    call SIGout

    ; Wipe sensitive data before sharing it
    ; with the transmission function

    call SIGrypt_wipe_sensitive

    test rax, rax
    js failed_post_mmap_A

    lea rdi, [newline]
    mov rsi, 1
    call SIGout

    lea rdi, [ciphertext_hex]

    mov rsi, [plaintext_len]
    add rsi, IV_len
    add rsi, HMAC_len
    add rsi, CRC_len
    shl rsi, 1
    add rsi, [time_buffer_len]
    add rsi, data_sep_len

    mov rdx, [module_FD]

    mov rcx, [frequency_ptr] 

    call SIGrypt_transmit

    test rax, rax
    jnz failed_post_mmap_A

destroy_A:

    mov rdi, r12
    mov rsi, block_size
    
    call destroy_block

    test rax, rax
    jz destroy_buffers

    lea rdi, [error_A]
    mov rsi, error_len
    
    call SIGout

destroy_buffers:
    call SIGrypt_wipe_buffers

    test rax, rax
    jnz failed_SIGrypt_buffer_wipes
    
    call SIGrypt_munlock_masters

terminate:

    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp

    mov rax, SYS_exit
    xor rdi, rdi
    syscall

failed_post_mmap_B:

    mov rax, SYS_munmap
    mov rdi, r14
    mov rsi, [fstat_buf + 48]
    syscall

    pop rbp

    jmp failed

failed_post_mmap_A:

    mov rdi, r12
    mov rsi, block_size
    
    call destroy_block

    test rax, rax
    jz failed

    lea rdi, [error_A]
    mov rsi, error_len
    
    call SIGout

failed:
   
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp

    mov rdi, rax
    mov rax, SYS_exit
    syscall

no_such_module:
    
    lea rdi, [USB_error]
    mov rsi, USB_error_len
    
    call SIGout

    jmp failed

Frequency_error:
    
    lea rdi, [Freq_error]
    mov rsi, Freq_error_len

    call SIGout

    jmp failed

key_input_failed:

    lea rdi, [Crit_prompt]
    mov rsi, Crit_prompt_len
      
    call SIGout

    jmp failed_post_mmap_A

failed_initial_key_wipe:

    lea rdi, [error_init]
    mov rsi, error_init_len

    call SIGout

    pop rbp

    jmp failed


failed_SIGrypt_buffer_wipes:
    
    lea rdi, [error_wipes]
    mov rsi, error_wipes_len

    call SIGout
    
    jmp failed_post_mmap_A
