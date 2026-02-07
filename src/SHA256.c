/* 
  ==========================================
  File: SHA256.c
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


      FUNCTION                          TEST VECTORS
  ==============================================================================
      SHA256            (SHA256ShortMsg.rsp, SHA256LongMsg.rsp, SHA256Monte.rsp)
      HMAC_SHA256       (HMAC.rsp)



NOT RECOMMENDED FOR USE OTHER THAN SIGRYPT
------------------------------------------
*/


typedef     unsigned    char            uint8_t     ;
typedef     unsigned    int             uint32_t    ;
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
// Operations: Page 10

static inline uint32_t rotate_r(uint32_t x, uint32_t n){

    return (x >> n) | (x << (32 - n));

}

static inline uint32_t choose(uint32_t x, uint32_t y, uint32_t z){
    
    return (x & y) ^ (~x & z);

}

static inline uint32_t majority(uint32_t x, uint32_t y, uint32_t z){

    return (x & y) ^ (x & z) ^ (y & z);

}

static inline uint32_t upper_sigma_A(uint32_t x){

    return rotate_r(x, 2) ^ rotate_r(x, 13) ^ rotate_r(x, 22);

}

static inline uint32_t upper_sigma_B(uint32_t x){

    return rotate_r(x, 6) ^ rotate_r(x, 11) ^ rotate_r(x, 25);

}

static inline uint32_t lower_sigma_A(uint32_t x){

    return rotate_r(x, 7) ^ rotate_r(x, 18) ^ (x >> 3);

}

static inline uint32_t lower_sigma_B(uint32_t x){

    return rotate_r(x, 17) ^ rotate_r(x, 19) ^ (x >> 10);

}


//  Validated (https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf)
//
//  Round Constants:    Page 11

static const uint32_t round_const[64] = {

    0X428A2F98U, 0X71374491U, 0XB5C0FBCFU, 0XE9B5DBA5U,
    0X3956C25BU, 0X59F111F1U, 0X923F82A4U, 0XAB1C5ED5U,
    0XD807AA98U, 0X12835B01U, 0X243185BEU, 0X550C7DC3U,
    0X72BE5D74U, 0X80DEB1FEU, 0X9BDC06A7U, 0XC19BF174U,
    0XE49B69C1U, 0XEFBE4786U, 0X0FC19DC6U, 0X240CA1CCU,
    0X2DE92C6FU, 0X4A7484AAU, 0X5CB0A9DCU, 0X76F988DAU,
    0X983E5152U, 0XA831C66DU, 0XB00327C8U, 0XBF597FC7U,
    0XC6E00BF3U, 0XD5A79147U, 0X06CA6351U, 0X14292967U,
    0X27B70A85U, 0X2E1B2138U, 0X4D2C6DFCU, 0X53380D13U,
    0X650A7354U, 0X766A0ABBU, 0X81C2C92EU, 0X92722C85U,
    0XA2BFE8A1U, 0XA81A664BU, 0XC24B8B70U, 0XC76C51A3U,
    0XD192E819U, 0XD6990624U, 0XF40E3585U, 0X106AA070U,
    0X19A4C116U, 0X1E376C08U, 0X2748774CU, 0X34B0BCB5U,
    0X391C0CB3U, 0X4ED8AA4AU, 0X5B9CCA4FU, 0X682E6FF3U,
    0X748F82EEU, 0X78A5636FU, 0X84C87814U, 0X8CC70208U,
    0X90BEFFFAU, 0XA4506CEBU, 0XBEF9A3F7U, 0XC67178F2U

};


//  Validated (https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf)
//
//  Computation:    Pages 22-23

static void compress(uint32_t hash_state[8], const uint8_t chunk[64]){

    /*
     Purpose:
            Helper function for sha256
            Compresses the text to hash
    
     Args:
            hash_state  -> NIST defined hash state
            chunk       -> text chunk
      
     Returns:
            None
    */

    uint32_t message_sched[64];

    for(int i = 0; i < 16; i++){

        message_sched[i] =  ((uint32_t)chunk[i*4+0] << 24)  | 
                            ((uint32_t)chunk[i*4+1] << 16)  |
                            ((uint32_t)chunk[i*4+2] << 8)   |
                            ((uint32_t)chunk[i*4+3] << 0)   ;

    }

    for(int i = 16; i < 64; i++){

        message_sched[i] =  lower_sigma_B(message_sched[i-2])   + 
                            message_sched[i-7]                  +
                            lower_sigma_A(message_sched[i-15])  +
                            message_sched[i-16]                 ;
    
    }

    uint32_t  A = hash_state[0],
              B = hash_state[1],
              C = hash_state[2],
              D = hash_state[3],
              E = hash_state[4],
              F = hash_state[5],
              G = hash_state[6],
              H = hash_state[7];

    for(int i = 0; i < 64; i++){

        uint32_t t_R =  H                 + 
                        upper_sigma_B(E)  + 
                        choose(E, F, G)   + 
                        round_const[i]    +
                        message_sched[i]  ;

        uint32_t t_L =  upper_sigma_A(A)  +
                        majority(A, B, C) ;

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

    zero_fill((uint8_t *)message_sched, 256);

}

//  Validated (https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf)
//
//  Hash states:    Page 15
//  Padding:        Page 8

int sha256(const uint8_t *message, size_t len, uint8_t out[32]){
    
    /*
     Purpose:
            Returns a sha256 tag in the "out" buffer
    
     Args:
            message -> bytes to hash
            len     -> length of bytes to hash
            out     -> destination buffer
      
     Returns:
            rax -> 0 on success
    */
    
    uint32_t hash_state[8] = {

        0X6A09E667U,0XBB67AE85U,0X3C6EF372U,0XA54FF53AU,
        0X510E527FU,0X9B05688CU,0X1F83D9ABU,0X5BE0CD19U

    };

    size_t i = 0;

    while(i + 64 <= len){

        compress(hash_state, message + i);
        i += 64;

    }

    uint8_t block[128];

    size_t remainder = len - i;

    for(size_t j = 0; j < remainder; j++){

        block[j] = message[i + j];

    }

    block[remainder] = 0x80;

    for(size_t j = remainder + 1; j < 128; j++){

        block[j] = 0;

    }
    
    uint64_t bitlen = (uint64_t)len * 8u;

    size_t pad_block_len = (remainder <= 55) ? 64 : 128;
    size_t off = pad_block_len - 8;

    for(int j = 0; j < 8; j++){

        block[off+j]  = (uint8_t)(bitlen >> 56-(j * 8));

    }

    compress(hash_state, block);

    if(pad_block_len == 128){   

      compress(hash_state, block + 64);

    }

    // Formats the 8 x 32-bit states into a 32-byte digest (big endian) 

    for(int j = 0; j < 8; j++){

        out[j*4+0] = (uint8_t)(hash_state[j] >> 24);
        out[j*4+1] = (uint8_t)(hash_state[j] >> 16);
        out[j*4+2] = (uint8_t)(hash_state[j] >> 8);
        out[j*4+3] = (uint8_t)(hash_state[j] >> 0);

    }

    zero_fill(block, 128);
    zero_fill((uint8_t *)hash_state, 32);

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

int hmac_sha256(const uint8_t *message, size_t len, const uint8_t *key, size_t key_size, uint8_t out[32]){ 

    /*
     Purpose:
            Returns a hmac_sha256 tag in the "out" buffer
    
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

    enum {block_size = 64,    // SHA256 uses 512 bit block, 512 / 8 = 64 byte
          hash_size  = 32} ;  // SHA256 hash size

    uint8_t ipad[block_size];
    uint8_t opad[block_size];

    uint8_t K0[block_size];
    for (size_t i = 0; i < 64; i++) { K0[i] = 0; }
        
    if(key_size > block_size){
    
        uint8_t comp_key[hash_size];

        sha256(key, key_size, comp_key);

        for(size_t i = 0; i < hash_size; i++) { K0[i] = comp_key[i]; }
    
        zero_fill(comp_key, hash_size);

    }

    else{

        for(size_t i = 0; i < key_size; i++) { K0[i] = key[i]; }

    }

    for(size_t i = 0; i < block_size; i++){

        ipad[i] = 0X36 ^ K0[i];
        opad[i] = 0X5C ^ K0[i];

    }

    uint8_t inner_hash[32]; 

    enum { max_mes_len = 3072 };

    if(len > (size_t)max_mes_len) { return -1; }

    uint8_t inner_buf[block_size + max_mes_len];

    uint8_t outer_buf[block_size + hash_size];

    concatenate(ipad, block_size, message, len, inner_buf, block_size + len);

    sha256(inner_buf, (size_t)(block_size + len), inner_hash);

    concatenate(opad, block_size, inner_hash, hash_size, outer_buf, block_size + hash_size);

    uint8_t outer_hash[hash_size];
    
    sha256(outer_buf, (size_t)(block_size + hash_size), outer_hash);

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


