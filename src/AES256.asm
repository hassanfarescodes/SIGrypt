; ==========================================
; File: AES256.asm
; Author: Hassan Fares
;
; Description:  Encrypts / Decrypts using
;               AES256-CTR 
;
; Assembler: NASM
; Architecture: x86-64
; ========================================== 


; Passed official NIST SP 800-38A CTR and IETF RFC3686 CTR official test vectors
; ------------------------------------------------------------------------------

BITS 64
DEFAULT REL

%include "../include/syscalls.inc"
%include "../include/data_block.inc"

section .text
global ENCRYPT_AES
global DECRYPT_AES

%macro KEY_HELPER_A 1

    aeskeygenassist xmm3, xmm2, %1
    pshufd xmm3, xmm3, 0xff
    movdqa xmm4, xmm1
    
    pslldq xmm4, 4
    pxor xmm1, xmm4

    pslldq xmm4, 4
    pxor xmm1, xmm4

    pslldq xmm4, 4
    pxor xmm1, xmm4

    pxor xmm1, xmm3

%endmacro


%macro KEY_HELPER_B 0

    aeskeygenassist xmm3, xmm1, 0x00
    pshufd xmm3, xmm3, 0xaa
    movdqa xmm4, xmm2

    pslldq xmm4, 4
    pxor xmm2, xmm4

    pslldq xmm4, 4
    pxor xmm2, xmm4

    pslldq xmm4, 4
    pxor xmm2, xmm4

    pxor xmm2, xmm3

%endmacro

%macro AES256_ENCRYPT 1

    pxor %1, [roundkeys + 0*16]
    
    aesenc %1, [roundkeys +  1*16]
    aesenc %1, [roundkeys +  2*16]
    aesenc %1, [roundkeys +  3*16]
    aesenc %1, [roundkeys +  4*16]
    aesenc %1, [roundkeys +  5*16]
    aesenc %1, [roundkeys +  6*16]
    aesenc %1, [roundkeys +  7*16]
    aesenc %1, [roundkeys +  8*16]
    aesenc %1, [roundkeys +  9*16]
    aesenc %1, [roundkeys + 10*16]
    aesenc %1, [roundkeys + 11*16]
    aesenc %1, [roundkeys + 12*16]
    aesenc %1, [roundkeys + 13*16]

    aesenclast %1, [roundkeys + 14*16]

%endmacro


expand_keys:

    push rbx
    
    movdqu xmm1, [AES_key]
    movdqu xmm2, [AES_key + 16]

    movdqu [roundkeys], xmm1
    movdqu [roundkeys + 16], xmm2

    KEY_HELPER_A 0x01
    movdqu [roundkeys + 2*16], xmm1
    KEY_HELPER_B
    movdqu [roundkeys + 3*16], xmm2

    KEY_HELPER_A 0x02
    movdqu [roundkeys + 4*16], xmm1
    KEY_HELPER_B
    movdqu [roundkeys + 5*16], xmm2

    KEY_HELPER_A 0x04
    movdqu [roundkeys + 6*16], xmm1
    KEY_HELPER_B
    movdqu [roundkeys + 7*16], xmm2

    KEY_HELPER_A 0x08
    movdqu [roundkeys + 8*16], xmm1
    KEY_HELPER_B
    movdqu [roundkeys + 9*16], xmm2

    KEY_HELPER_A 0x10
    movdqu [roundkeys + 10*16], xmm1
    KEY_HELPER_B
    movdqu [roundkeys + 11*16], xmm2

    KEY_HELPER_A 0x20
    movdqu [roundkeys + 12*16], xmm1
    KEY_HELPER_B
    movdqu [roundkeys + 13*16], xmm2

    KEY_HELPER_A 0x40
    movdqu [roundkeys + 14*16], xmm1

    pop rbx
    
    ret


inc_IV:

    mov rax, [IV_copy + 8]
    bswap rax
    add rax, 1
    jc overflowed_IV 
    bswap rax
    mov [IV_copy + 8], rax

    xor rax, rax
    
    ret


overflowed_IV:

    mov rax, 1

    ret
    

ENCRYPT_AES:

    ; Purpose:
    ;       Encrypts "plaintext" in data block and writes
    ;       "ciphertext" to data block
    ;
    ; Args:
    ;       rdi -> start address of data block
    ;       Uses:   plaintext_len , IV_copy, key_schedule
    ;               AES_key, roundkeys
    ;
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure
    ;       rax -> 1 on IV overflow
    ;       rax -> 2 on compatibility failure


    push rbp
    push r12
    push rbx

    mov r12, rdi

    ; First check to see if CPU supports AES instructions
    mov rax, 1

    cpuid   ; Returns to 32-bit registers

    bt ecx, 25

    jc compatible   ; CPU supports AES instructions

    pop rbx
    pop r12
    pop rbp

    mov rax, 2
    ret


compatible:

    call expand_keys

    movdqu xmm1, [IV]
    movdqu [IV_copy], xmm1

    lea rsi, [plaintext]
    lea rdi, [ciphertext]
    mov rbx, qword [plaintext_len]


encrypt:
    cmp rbx, 16
    jb tail

    movdqu xmm0, [IV_copy]
    AES256_ENCRYPT xmm0

    movdqu xmm1, [rsi]
    pxor xmm1, xmm0
    movdqu [rdi], xmm1

    add rsi, 16
    add rdi, 16
    sub rbx, 16
    call inc_IV
    test rax, rax
    jnz failed
    jmp encrypt


tail:
    
    test rbx, rbx
    jz encrypted

    movdqu xmm0, [IV_copy]
    AES256_ENCRYPT xmm0
    movdqu [key_schedule], xmm0

    xor r8, r8


encrypt_tail:
    
    mov al, [rsi + r8]
    xor al, [key_schedule + r8]
    mov [rdi + r8], al

    inc r8
    cmp r8, rbx
    jb encrypt_tail

    call inc_IV
    test rax, rax
    jnz failed

    jmp encrypted


DECRYPT_AES:

    ; Purpose:
    ;       Decrypts "ciphertext" in data block and writes
    ;       "decrypted" to data block
    ;
    ; Args:
    ;       rdi -> start address of data block
    ;       Uses:   ciphertext, plaintext_len , IV_copy, 
    ;               key_schedule, AES_key, roundkeys
    ;
    ; Returns:
    ;       rax -> 0 on success
    ;       rax -> -1 on failure

    push rbx
    push r12
    push rbp

    mov r12, rdi

    call expand_keys

    movdqu xmm1, [IV]
    movdqu [IV_copy], xmm1

    lea rsi, [ciphertext]
    lea rdi, [decrypted]
    mov rbx, qword [plaintext_len]          ; plaintext length is same as ciphertext length in AES-CTR

    jmp encrypt                             ; AES-CTR encryption is inverse to decryption, "encrypt" again to decrypt due to XOR nature


encrypted:
  
    pop rbx
    pop r12
    pop rbp

    xor rax, rax
    ret


failed:

    pop rbx
    pop r12
    pop rbp

    mov rax, -1
    ret
