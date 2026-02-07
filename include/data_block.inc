%define ciphertext      (r12)           ; 1024 bytes
%define decrypted       (r12 + 1024)    ; 1024 bytes
%define plaintext       (r12 + 2048)    ; 1024 bytes
%define roundkeys       (r12 + 3072)    ; 240 bytes
%define HMAC_hex        (r12 + 3312)    ; 64 bytes
%define HMAC            (r12 + 3376)    ; 32 bytes
%define HMAC_key        (r12 + 3408)    ; 32 bytes
%define AES_key         (r12 + 3440)    ; 32 bytes
%define IV_hex          (r12 + 3472)    ; 32 bytes
%define CRC_tag_hex     (r12 + 3504)    ; 16 bytes
%define IV              (r12 + 3520)    ; 16 bytes
%define IV_copy         (r12 + 3536)    ; 16 bytes
%define key_schedule    (r12 + 3552)    ; 16 bytes
%define plaintext_len   (r12 + 3568)    ; 8 bytes
%define CRC_tag         (r12 + 3576)    ; 8 bytes
%define block_size      4096            ; 3584
