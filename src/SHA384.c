/* 
  ==========================================
  File: SHA384.c
  Author: Hassan Fares

  Description:  Handles authentication
                and integrity
 
  Assembler: gcc
  Architecture: x86-64      (SIGrypt file)
  ==========================================
*/


/* 
 Passed official NIST test vectors:
 ----------------------------------


       FUNCTIONS                            TEST VECTORS
      ===========       ======================================================
      SHA384            SHA384ShortMsg.rsp, SHA384LongMsg.rsp, SHA384Monte.rsp
      HMAC_SHA384       HMAC.rsp



NOT RECOMMENDED FOR USE OTHER THAN SIGRYPT
------------------------------------------
*/


typedef     unsigned    char            uint8_t     ;
typedef     unsigned    long    long    uint64_t    ;
typedef     unsigned    long            size_t      ;


extern long sys_write(int fd, const void *buf, size_t len);
extern size_t sys_strlen(const char *s);



static void write_all(int fd, const void *buf, size_t len){

    const uint8_t *printable = (const uint8_t*) buf;

    while(len){
        long return_code = sys_write(fd, printable, len);

        if (return_code <= 0) return;

        printable += (size_t) return_code;
        len -= (size_t) return_code;
    }
}

int zero_fill(uint8_t *p, size_t n) {

    if (n == 0) return 0;
    if (!p) return -1;

    while (n--){

        *(volatile uint8_t *)p++ = 0;

    }

    return 0;
}

static void write_str(int fd, const char *s){
    
    write_all(fd, s, sys_strlen(s));

}


// Validated (https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf)
//
// Operations: Page 11

static inline uint64_t rotate_r(uint64_t x, uint64_t n){

    return (x >> n) | (x << (64 - n));

}

static inline uint64_t choose(uint64_t x, uint64_t y, uint64_t z){
    
    return (x & y) ^ (~x & z);

}

static inline uint64_t majority(uint64_t x, uint64_t y, uint64_t z){

    return (x & y) ^ (x & z) ^ (y & z);

}

static inline uint64_t upper_sigma_A(uint64_t x){

    return rotate_r(x, 28) ^ rotate_r(x, 34) ^ rotate_r(x, 39);

}

static inline uint64_t upper_sigma_B(uint64_t x){

    return rotate_r(x, 14) ^ rotate_r(x, 18) ^ rotate_r(x, 41);

}

static inline uint64_t lower_sigma_A(uint64_t x){

    return rotate_r(x,1) ^ rotate_r(x, 8) ^ (x >> 7);

}

static inline uint64_t lower_sigma_B(uint64_t x){

    return rotate_r(x, 19) ^ rotate_r(x, 61) ^ (x >> 6);

}


//  Validated (https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf)
//
//  Round Constants:    Page 12

static const uint64_t round_const[80] = {

    0X428A2F98D728AE22ULL, 0X7137449123EF65CDULL, 0XB5C0FBCFEC4D3B2FULL, 0XE9B5DBA58189DBBCULL, 
    0X3956C25BF348B538ULL, 0X59F111F1B605D019ULL, 0X923F82A4AF194F9BULL, 0XAB1C5ED5DA6D8118ULL, 
    0XD807AA98A3030242ULL, 0X12835B0145706FBEULL, 0X243185BE4EE4B28CULL, 0X550C7DC3D5FFB4E2ULL, 
    0X72BE5D74F27B896FULL, 0X80DEB1FE3B1696B1ULL, 0X9BDC06A725C71235ULL, 0XC19BF174CF692694ULL, 
    0XE49B69C19EF14AD2ULL, 0XEFBE4786384F25E3ULL, 0X0FC19DC68B8CD5B5ULL, 0X240CA1CC77AC9C65ULL, 
    0X2DE92C6F592B0275ULL, 0X4A7484AA6EA6E483ULL, 0X5CB0A9DCBD41FBD4ULL, 0X76F988DA831153B5ULL, 
    0X983E5152EE66DFABULL, 0XA831C66D2DB43210ULL, 0XB00327C898FB213FULL, 0XBF597FC7BEEF0EE4ULL, 
    0XC6E00BF33DA88FC2ULL, 0XD5A79147930AA725ULL, 0X06CA6351E003826FULL, 0X142929670A0E6E70ULL, 
    0X27B70A8546D22FFCULL, 0X2E1B21385C26C926ULL, 0X4D2C6DFC5AC42AEDULL, 0X53380D139D95B3DFULL, 
    0X650A73548BAF63DEULL, 0X766A0ABB3C77B2A8ULL, 0X81C2C92E47EDAEE6ULL, 0X92722C851482353BULL, 
    0XA2BFE8A14CF10364ULL, 0XA81A664BBC423001ULL, 0XC24B8B70D0F89791ULL, 0XC76C51A30654BE30ULL, 
    0XD192E819D6EF5218ULL, 0XD69906245565A910ULL, 0XF40E35855771202AULL, 0X106AA07032BBD1B8ULL, 
    0X19A4C116B8D2D0C8ULL, 0X1E376C085141AB53ULL, 0X2748774CDF8EEB99ULL, 0X34B0BCB5E19B48A8ULL, 
    0X391C0CB3C5C95A63ULL, 0X4ED8AA4AE3418ACBULL, 0X5B9CCA4F7763E373ULL, 0X682E6FF3D6B2B8A3ULL, 
    0X748F82EE5DEFB2FCULL, 0X78A5636F43172F60ULL, 0X84C87814A1F0AB72ULL, 0X8CC702081A6439ECULL, 
    0X90BEFFFA23631E28ULL, 0XA4506CEBDE82BDE9ULL, 0XBEF9A3F7B2C67915ULL, 0XC67178F2E372532BULL, 
    0XCA273ECEEA26619CULL, 0XD186B8C721C0C207ULL, 0XEADA7DD6CDE0EB1EULL, 0XF57D4F7FEE6ED178ULL, 
    0X06F067AA72176FBAULL, 0X0A637DC5A2C898A6ULL, 0X113F9804BEF90DAEULL, 0X1B710B35131C471BULL, 
    0X28DB77F523047D84ULL, 0X32CAAB7B40C72493ULL, 0X3C9EBE0A15C9BEBCULL, 0X431D67C49C100D4CULL, 
    0X4CC5D4BECB3E42B6ULL, 0X597F299CFC657E2AULL, 0X5FCB6FAB3AD6FAECULL, 0X6C44198C4A475817ULL

};


//  Validated (https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf)
//
//  Computation:    Pages 22-23

static void compress(uint64_t hash_state[8], const uint8_t chunk[128]){

    /*
     Purpose:
            Helper function for sha384
            Compresses the text to hash
    
     Args:
            hash_state  -> NIST defined hash state
            chunk       -> text chunk
      
     Returns:
            None
    */

    uint64_t message_sched[80];

    for(int i = 0; i < 16; i++){

        message_sched[i] =  ((uint64_t)chunk[i*8+0] << 56)  | 
                            ((uint64_t)chunk[i*8+1] << 48)  |
                            ((uint64_t)chunk[i*8+2] << 40)  |
                            ((uint64_t)chunk[i*8+3] << 32)  |
                            ((uint64_t)chunk[i*8+4] << 24)  |
                            ((uint64_t)chunk[i*8+5] << 16)  |
                            ((uint64_t)chunk[i*8+6] << 8)   |
                            ((uint64_t)chunk[i*8+7] << 0);

    }

    for(int i = 16; i < 80; i++){

        message_sched[i] =  lower_sigma_B(message_sched[i-2])   + 
                            message_sched[i-7]                  +
                            lower_sigma_A(message_sched[i-15])  +
                            message_sched[i-16];
    
    }

    uint64_t  A = hash_state[0],
              B = hash_state[1],
              C = hash_state[2],
              D = hash_state[3],
              E = hash_state[4],
              F = hash_state[5],
              G = hash_state[6],
              H = hash_state[7];

    for(int i = 0; i < 80; i++){

        uint64_t t_R =  H                   + 
                        upper_sigma_B(E)    +  
                        choose(E, F, G)     + 
                        round_const[i]      +
                        message_sched[i];

        uint64_t t_L =  upper_sigma_A(A)    +
                        majority(A, B, C);

        H = G;

        G = F;

        F = E;

        E = D + t_R;

        D = C;

        C = B;

        B = A;

        A = t_R + t_L;

    }

    hash_state[0] += A;
    hash_state[1] += B;
    hash_state[2] += C;
    hash_state[3] += D;
    hash_state[4] += E;
    hash_state[5] += F;
    hash_state[6] += G;
    hash_state[7] += H;

    zero_fill((uint8_t *)message_sched, 640);

}

//  Validated (https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf)
//
//  Hash states:    Page 15
//  Padding:        Page 8

int sha384(const uint8_t *message, size_t len, uint8_t out[48]){
    
    /*
     Purpose:
            Returns a sha384 tag in the "out" buffer
    
     Args:
            message -> bytes to hash
            len     -> length of bytes to hash
            out     -> destination buffer
      
     Returns:
            rax -> 0 on success
    */
    
    uint64_t hash_state[8] = {

        0XCBBB9D5DC1059ED8ULL, 0X629A292A367CD507ULL, 
        0X9159015A3070DD17ULL, 0X152FECD8F70E5939ULL, 
        0X67332667FFC00B31ULL, 0X8EB44A8768581511ULL, 
        0XDB0C2E0D64F98FA7ULL, 0X47B5481DBEFA4FA4ULL

    };

    size_t i = 0;

    while(i + 128 <= len){

        compress(hash_state, message + i);
        i += 128;

    }

    uint8_t block[256];

    size_t remainder = len - i;

    for(size_t j = 0; j < remainder; j++){

        block[j] = message[i + j];

    }

    block[remainder] = 0x80;
    size_t pad_block_len = (remainder <= 111) ? 128 : 256;

    for(size_t j = remainder + 1; j < pad_block_len; j++){

        block[j] = 0;

    }
    
    uint64_t bitlen = (uint64_t)len * 8ULL;

    size_t off = pad_block_len - 8;

    for(int j = 0; j < 8; j++){

        block[off+j]  = (uint8_t)(bitlen >> (56 - (j * 8)));

    }

    compress(hash_state, block);

    if(pad_block_len == 256){   

      compress(hash_state, block + 128);

    }

    // Formats the 8 x 32-bit states into a 32-byte digest (big endian) 

    for(int j = 0; j < 6; j++){

        out[j*8+0] = (uint8_t)(hash_state[j] >> 56);
        out[j*8+1] = (uint8_t)(hash_state[j] >> 48);
        out[j*8+2] = (uint8_t)(hash_state[j] >> 40);
        out[j*8+3] = (uint8_t)(hash_state[j] >> 32);
        out[j*8+4] = (uint8_t)(hash_state[j] >> 24);
        out[j*8+5] = (uint8_t)(hash_state[j] >> 16);
        out[j*8+6] = (uint8_t)(hash_state[j] >> 8);
        out[j*8+7] = (uint8_t)(hash_state[j] >> 0);

    }

    zero_fill(block, 256);
    zero_fill((uint8_t *)hash_state, 64);

    return 0;

}

int concatenate(const uint8_t *src, size_t src_len, const uint8_t *dst, size_t dst_len, uint8_t *out, size_t out_limit){

    if(src_len > out_limit)             { return -1; }
    if(dst_len > out_limit - src_len)   { return -1; }
    
    size_t i;

    for(i = 0; i < src_len; i++){
        out[i] = src[i]; 
    }

    for(i = 0; i < dst_len; i++){
        out[src_len+i] = dst[i]; 
    }

    return 0;

}

// Validated (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf)
//
// Algorithm:   Page 4

int hmac_sha384(const uint8_t *message, size_t len, const uint8_t *key, size_t key_size, uint8_t out[48]){ 

    /*
     Purpose:
            Returns a hmac_sha384 tag in the "out" buffer
    
     Args:
            message -> bytes to hash
            len     -> length of bytes to hash
            key     -> hmac key
            key_size-> size of the hmac key
            out     -> destination buffer
      
     Returns:
            rax -> 0 on success
            rax -> -1 on failure
    */

    if (!out) return -1;
    if (len && !message) return -1;
    if (key_size && !key) return -1;

    enum {block_size = 128,    // SHA384 uses 1024 bit block, 1024 / 8 = 128 byte
          hash_size  = 48} ;  // SHA384 hash size

    uint8_t ipad[block_size];
    uint8_t opad[block_size];

    uint8_t K0[block_size];

    for (size_t i = 0; i < block_size; i++) { 

      K0[i] = 0; 

    }
        
    if(key_size > block_size){
    
        uint8_t comp_key[hash_size];

        sha384(key, key_size, comp_key);

        for(size_t i = 0; i < hash_size; i++) { 

          K0[i] = comp_key[i]; 

        }
    
        zero_fill(comp_key, hash_size);

    }

    else{

        for(size_t i = 0; i < key_size; i++) { 

          K0[i] = key[i]; 

        }

    }

    for(size_t i = 0; i < block_size; i++){

        ipad[i] = 0X36 ^ K0[i];
        opad[i] = 0X5C ^ K0[i];

    }

    uint8_t inner_hash[hash_size]; 

    enum { max_mes_len = 3072 };

    if(len > (size_t)max_mes_len) { return -1; }

    uint8_t inner_buf[block_size + max_mes_len];

    uint8_t outer_buf[block_size + hash_size];

    concatenate(ipad, block_size, message, len, inner_buf, sizeof(inner_buf));

    sha384(inner_buf, (size_t)(block_size + len), inner_hash);

    concatenate(opad, block_size, inner_hash, hash_size, outer_buf, sizeof(outer_buf));

    uint8_t outer_hash[hash_size];
    
    sha384(outer_buf, (size_t)(block_size + hash_size), outer_hash);

    for(size_t i = 0; i < hash_size; i++){

        out[i] = outer_hash[i];

    }

    zero_fill(inner_hash, hash_size);
    zero_fill(inner_buf, block_size+len);
    zero_fill(outer_buf, block_size+hash_size);
    zero_fill(K0, block_size);
    zero_fill(ipad, block_size);
    zero_fill(opad, block_size);

    return 0;
}
