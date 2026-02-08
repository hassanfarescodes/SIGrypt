%define ciphertext      (r12)           ; 1024 bytes
%define decrypted       (r12 + 1024)    ; 1024 bytes
%define plaintext       (r12 + 2048)    ; 1024 bytes
%define roundkeys       (r12 + 3072)    ; 240 bytes
%define HMAC_hex        (r12 + 3312)    ; 128 bytes
%define HMAC            (r12 + 3440)    ; 48 bytes
%define HMAC_key        (r12 + 3488)    ; 48 bytes
%define AES_key         (r12 + 3536)    ; 48 bytes
%define IV_hex          (r12 + 3584)    ; 32 bytes
%define CRC_tag_hex     (r12 + 3616)    ; 16 bytes
%define IV              (r12 + 3632)    ; 16 bytes
%define IV_copy         (r12 + 3648)    ; 16 bytes
%define key_schedule    (r12 + 3664)    ; 16 bytes
%define plaintext_len   (r12 + 3680)    ; 8 bytes
%define CRC_tag         (r12 + 3688)    ; 8 bytes
%define block_size      4096            ; 3696
