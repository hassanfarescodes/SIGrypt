; ==========================================
; File: CRC.asm
; Author: Hassan Fares
; Description: CRC Source File
; Assembler: NASM
; Architecture: x86-64
; ==========================================

BITS 64

DEFAULT REL

%include "../include/syscalls.inc"
%include "../include/data_block.inc"

section .text
    global SIGrypt_CRC_ECMA182
    global SIGrypt_CRC_Validate

SIGrypt_CRC_Validate:
    
    ; Purpose:
    ;       Computes CRC-64 ECMA182 Checksum
    ;       and checks it against another checksum
    ;       Expects r12 to be address of data block
    ;
    ; Args:
    ;       rdi -> address of buffer
    ;       rsi -> size of buffer
    ;       rdx -> address of checksum
    ;
    ; Returns:
    ;       rax -> 0 on true
    ;       rax -> 1 on false

    push rbx

    lea rbx, [rdx]

    call SIGrypt_CRC_ECMA182

    mov rcx, [CRC_tag]
    mov rdx, [rbx]

    cmp rcx, rdx

    sete al

    xor rax, 1

    pop rbx
    ret
      
    

SIGrypt_CRC_ECMA182:

    ; Purpose:
    ;       Computes CRC-64 ECMA182 Checksum
    ;
    ; Args:
    ;       rdi -> address of buffer
    ;       rsi -> size of buffer
    ;       Expects r12 to be address of data block
    ;
    ; Returns:
    ;       rax -> 0 on success

    push rbx

    mov r8, rsi
    mov rsi, rdi
    add rsi, r8

    mov rbx, 0x0000000000000000 ;    <----- CRC-64 ECMA182 Initial CRC
    mov r10, 0x42F0E1EBA9EA3693 ;    <----- CRC-64 ECMA182 Initial Generator

CRC_algorithm:

    ; for each byte b in message:
    ;     crc = crc XOR (b << 56)
    ;     repeat 8 times:
    ;         if (crc & & 0x8000000000000000) != 0:
    ;             crc = (crc << 1) XOR 0x42F0E1EBA9EA3693
    ;         else
    ;             crc = crc << 1
    
    cmp rdi, rsi
    je done

    movzx rax, byte [rdi]
    shl rax, 56
    xor rbx, rax

    mov rcx, 8

    MSB_loop:
        shl rbx, 1
        jnc skip_xor
        xor rbx, r10

    skip_xor:
        loop MSB_loop

    next_byte:
        inc rdi
        jmp CRC_algorithm

done:
    bswap rbx
    mov [CRC_tag], rbx

exit:
    
    pop rbx

    xor rax, rax
    ret
