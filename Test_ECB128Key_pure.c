// aes_kat_tester_noopenssl.c
// Compile: cc aes_kat_tester_noopenssl.c -o aes_kat_tester_noopenssl
// Usage: ./aes_kat_tester_noopenssl <rsp_file>
// Returns 0 if all pass, 2 if any fail, 1 on error.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/* ---------------------- AES implementation (tiny-AES style) ---------------------- */
/* This AES implementation supports 128/192/256-bit keys for ECB encryption. */

/* AES parameters */
#define AES_BLOCK_SIZE 16

typedef struct {
    uint32_t round_key[60]; // enough for 14 rounds * 4 words = 56, allocate 60 for safety
    int Nr; // number of rounds
} AES_KEY_LOCAL;

/* Forward S-box */
static const uint8_t sbox[256] = {
  /* 0x00 */ 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  /* 0x10 */ 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  /* 0x20 */ 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  /* 0x30 */ 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  /* 0x40 */ 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  /* 0x50 */ 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  /* 0x60 */ 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  /* 0x70 */ 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  /* 0x80 */ 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  /* 0x90 */ 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  /* 0xA0 */ 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  /* 0xB0 */ 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  /* 0xC0 */ 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  /* 0xD0 */ 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  /* 0xE0 */ 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  /* 0xF0 */ 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Round constant */
static const uint32_t Rcon[15] = {
    0x00000000UL, 0x01000000UL, 0x02000000UL, 0x04000000UL,
    0x08000000UL, 0x10000000UL, 0x20000000UL, 0x40000000UL,
    0x80000000UL, 0x1b000000UL, 0x36000000UL, 0x6c000000UL,
    0xd8000000UL, 0xab000000UL, 0x4d000000UL
};

/* Helper macros */
#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] << 8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st) \
    (ct)[0] = (uint8_t)((st) >> 24); \
    (ct)[1] = (uint8_t)((st) >> 16); \
    (ct)[2] = (uint8_t)((st) >> 8); \
    (ct)[3] = (uint8_t)(st);

/* Multiply in GF(2^8) */
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t res = 0;
    while (b) {
        if (b & 1) res ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return res;
}

/* Key expansion for 128/192/256 bit keys */
static int AES_set_encrypt_key_local(const uint8_t *userKey, const int bits, AES_KEY_LOCAL *key) {
    if (!userKey || !key) return -1;
    int Nk = bits / 32;
    int Nr;
    if (Nk == 4) Nr = 10;
    else if (Nk == 6) Nr = 12;
    else if (Nk == 8) Nr = 14;
    else return -1;
    key->Nr = Nr;
    uint32_t temp;
    uint32_t *rk = key->round_key;
    int i = 0;
    // copy initial key to round_key (word-wise)
    for (i = 0; i < Nk; ++i) {
        rk[i] = ((uint32_t)userKey[4*i] << 24) |
                ((uint32_t)userKey[4*i+1] << 16) |
                ((uint32_t)userKey[4*i+2] << 8) |
                ((uint32_t)userKey[4*i+3]);
    }
    i = Nk;
    int total_words = 4 * (Nr + 1);
    while (i < total_words) {
        temp = rk[i - 1];
        if (i % Nk == 0) {
            // RotWord + SubWord + Rcon
            uint32_t t = (temp << 8) | (temp >> 24);
            uint32_t s = ((uint32_t)sbox[(t >> 24) & 0xFF] << 24) |
                         ((uint32_t)sbox[(t >> 16) & 0xFF] << 16) |
                         ((uint32_t)sbox[(t >> 8) & 0xFF] << 8) |
                         ((uint32_t)sbox[t & 0xFF]);
            temp = s ^ Rcon[i / Nk];
        } else if (Nk > 6 && (i % Nk) == 4) {
            // extra SubWord for 256-bit keys
            uint32_t s = ((uint32_t)sbox[(temp >> 24) & 0xFF] << 24) |
                         ((uint32_t)sbox[(temp >> 16) & 0xFF] << 16) |
                         ((uint32_t)sbox[(temp >> 8) & 0xFF] << 8) |
                         ((uint32_t)sbox[temp & 0xFF]);
            temp = s;
        }
        rk[i] = rk[i - Nk] ^ temp;
        i++;
    }
    return 0;
}

/* AddRoundKey */
static void AddRoundKey(uint8_t state[16], const uint32_t *rk) {
    for (int i = 0; i < 4; ++i) {
        uint32_t k = rk[i];
        state[4*i + 0] ^= (uint8_t)(k >> 24);
        state[4*i + 1] ^= (uint8_t)(k >> 16);
        state[4*i + 2] ^= (uint8_t)(k >> 8);
        state[4*i + 3] ^= (uint8_t)(k);
    }
}

/* SubBytes */
static void SubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
}

/* ShiftRows */
static void ShiftRows(uint8_t state[16]) {
    uint8_t tmp[16];
    tmp[0]  = state[0];
    tmp[1]  = state[5];
    tmp[2]  = state[10];
    tmp[3]  = state[15];
    tmp[4]  = state[4];
    tmp[5]  = state[9];
    tmp[6]  = state[14];
    tmp[7]  = state[3];
    tmp[8]  = state[8];
    tmp[9]  = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];
    memcpy(state, tmp, 16);
}

/* MixColumns */
static void MixColumns(uint8_t state[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t *col = state + 4*c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        uint8_t r0 = (uint8_t)(mul(0x02, a0) ^ mul(0x03, a1) ^ a2 ^ a3);
        uint8_t r1 = (uint8_t)(a0 ^ mul(0x02, a1) ^ mul(0x03, a2) ^ a3);
        uint8_t r2 = (uint8_t)(a0 ^ a1 ^ mul(0x02, a2) ^ mul(0x03, a3));
        uint8_t r3 = (uint8_t)(mul(0x03, a0) ^ a1 ^ a2 ^ mul(0x02, a3));
        col[0] = r0; col[1] = r1; col[2] = r2; col[3] = r3;
    }
}

/* AES block encryption using expanded round keys in key->round_key */
static void AES_ecb_encrypt_local(const uint8_t in[16], uint8_t out[16], const AES_KEY_LOCAL *key) {
    uint8_t state[16];
    memcpy(state, in, 16);
    int Nr = key->Nr;
    const uint32_t *rk = key->round_key;
    // initial round key
    AddRoundKey(state, rk);
    rk += 4;
    // Nr - 1 full rounds
    for (int round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, rk);
        rk += 4;
    }
    // final round (no MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, rk);
    memcpy(out, state, 16);
}

/* ---------------------- End AES implementation ---------------------- */

/* ---------------------- Utility functions from original tester ---------------------- */

static void rstrip(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1]=='\n' || s[n-1]=='\r' || s[n-1]==' ' || s[n-1]=='\t')) n--;
    s[n] = '\0';
}
static void lstrip_inplace(char **s_ptr) {
    if (!s_ptr || !*s_ptr) return;
    char *s = *s_ptr;
    while (*s && isspace((unsigned char)*s)) s++;
    *s_ptr = s;
}

/* hex (ascii) -> bytes. returns number of bytes or -1 if invalid */
static int hex2bin_len(const char *hex, uint8_t *out, size_t out_max) {
    if (!hex || !out) return -1;
    /* skip spaces inside string */
    size_t hexchars = 0;
    for (const char *p = hex; *p; ++p) if (!isspace((unsigned char)*p)) hexchars++;
    if (hexchars % 2 != 0) return -1;
    size_t bytes = hexchars / 2;
    if (bytes > out_max) return -1;
    size_t j = 0;
    unsigned int hi = 0;
    int have_hi = 0;
    for (const char *p = hex; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (isspace(c)) continue;
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') v = 10 + (c - 'A');
        else return -1;
        if (!have_hi) { hi = v << 4; have_hi = 1; }
        else { out[j++] = (uint8_t)(hi | v); have_hi = 0; }
    }
    return (int)bytes;
}

static void bin2hex_str(const uint8_t *in, size_t inlen, char *out, size_t out_max) {
    static const char hexch[] = "0123456789abcdef";
    if (!in || !out) return;
    if (out_max < inlen*2 + 1) { out[0]=0; return; }
    for (size_t i=0;i<inlen;i++){
        out[2*i]   = hexch[(in[i]>>4)&0xF];
        out[2*i+1] = hexch[in[i]&0xF];
    }
    out[2*inlen] = '\0';
}

static void print_hex_label(const char *label, const uint8_t *buf, size_t len) {
    char *tmp = malloc(len*2 + 1);
    if (!tmp) return;
    bin2hex_str(buf, len, tmp, len*2 + 1);
    printf("%s: %s\n", label, tmp);
    free(tmp);
}

/* ---------------------- Main tester (adapted from user-provided code) ---------------------- */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <rsp_file>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("fopen"); return 1; }

    char raw[4096];
    char key_hex[2048] = {0}, pt_hex[16384] = {0}, ct_hex[16384] = {0};
    int have_key = 0, have_pt = 0, have_ct = 0;
    int total = 0, passed = 0, failed = 0;
    int current_count = -1;

    while (fgets(raw, sizeof(raw), fp)) {
        rstrip(raw);
        char *line = raw;
        lstrip_inplace(&line);
        if (line[0] == '\0') continue;
        if (line[0] == '#') continue;
        if (line[0] == '[') {
            printf("DEBUG: Section=%s\n", line);
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = line; char *v = eq + 1;
        rstrip(k); lstrip_inplace(&k);
        rstrip(v); lstrip_inplace(&v);

        if (strcasecmp(k, "COUNT") == 0) {
            current_count = atoi(v);
            have_key = have_pt = have_ct = 0;
            key_hex[0] = pt_hex[0] = ct_hex[0] = '\0';
        } else if (strcasecmp(k, "KEY") == 0) {
            strncpy(key_hex, v, sizeof(key_hex)-1);
            have_key = 1;
        } else if (strcasecmp(k, "PLAINTEXT") == 0 || strcasecmp(k, "PT") == 0) {
            strncpy(pt_hex, v, sizeof(pt_hex)-1);
            have_pt = 1;
        } else if (strcasecmp(k, "CIPHERTEXT") == 0 || strcasecmp(k, "CT") == 0) {
            strncpy(ct_hex, v, sizeof(ct_hex)-1);
            have_ct = 1;
        } else {
            continue;
        }

        if (have_key && have_pt && have_ct) {
            total++;
            printf("========================================\n");
            printf("VECTOR COUNT=%d (vector #%d)\n", current_count, total);

            uint8_t key_buf[32];
            int key_bytes = hex2bin_len(key_hex, key_buf, sizeof(key_buf));
            if (key_bytes <= 0) {
                printf("ERROR: invalid KEY hex (len=%ld) -> '%s'\n", strlen(key_hex), key_hex);
                failed++;
                goto cleanup_vector;
            }

            size_t pt_hex_len = strlen(pt_hex);
            size_t ct_hex_len = strlen(ct_hex);
            if (pt_hex_len == 0 || ct_hex_len == 0) {
                printf("ERROR: empty PT or CT\n");
                failed++;
                goto cleanup_vector;
            }
            size_t pt_bytes_max = pt_hex_len/2;
            size_t ct_bytes_max = ct_hex_len/2;
            if (pt_bytes_max == 0 || ct_bytes_max == 0) {
                printf("ERROR: invalid PT/CT hex lengths\n");
                failed++;
                goto cleanup_vector;
            }
            uint8_t *pt_buf = malloc(pt_bytes_max);
            uint8_t *ct_buf = malloc(ct_bytes_max);
            if (!pt_buf || !ct_buf) { perror("malloc"); free(pt_buf); free(ct_buf); failed++; goto cleanup_vector; }

            int pt_bytes = hex2bin_len(pt_hex, pt_buf, pt_bytes_max);
            int ct_bytes = hex2bin_len(ct_hex, ct_buf, ct_bytes_max);
            if (pt_bytes <= 0 || ct_bytes <= 0) {
                printf("ERROR: invalid PT/CT hex\n");
                free(pt_buf); free(ct_buf);
                failed++;
                goto cleanup_vector;
            }

            if (pt_bytes != ct_bytes) {
                printf("WARNING: PT and CT lengths differ (%d vs %d). Will compare up to min length.\n", pt_bytes, ct_bytes);
            }
            if ((pt_bytes % AES_BLOCK_SIZE) != 0) {
                printf("ERROR: plaintext length %d is not multiple of AES block size\n", pt_bytes);
                free(pt_buf); free(ct_buf);
                failed++;
                goto cleanup_vector;
            }

            uint8_t *out_buf = malloc(pt_bytes);
            if (!out_buf) { perror("malloc"); free(pt_buf); free(ct_buf); failed++; goto cleanup_vector; }
            memset(out_buf, 0, pt_bytes);

            AES_KEY_LOCAL aes_key_local;
            int key_bits = key_bytes * 8;
            if (!(key_bits == 128 || key_bits == 192 || key_bits == 256)) {
                printf("ERROR: unsupported key size %d bits\n", key_bits);
                free(pt_buf); free(ct_buf); free(out_buf); failed++; goto cleanup_vector;
            }
            if (AES_set_encrypt_key_local(key_buf, key_bits, &aes_key_local) != 0) {
                printf("ERROR: AES_set_encrypt_key_local failed\n");
                free(pt_buf); free(ct_buf); free(out_buf); failed++; goto_cleanup_vector2:
                ;
            }

            for (int i = 0; i < pt_bytes; i += AES_BLOCK_SIZE) {
                AES_ecb_encrypt_local(pt_buf + i, out_buf + i, &aes_key_local);
            }

            print_hex_label("  KEY", key_buf, key_bytes);
            print_hex_label("  PLAINTEXT", pt_buf, pt_bytes);
            print_hex_label("  EXPECTED CIPHERTEXT", ct_buf, ct_bytes);
            print_hex_label("  CALCULATED CIPHERTEXT", out_buf, pt_bytes);

            int ok = 1;
            int cmp_len = (pt_bytes < ct_bytes) ? pt_bytes : ct_bytes;
            if (memcmp(out_buf, ct_buf, cmp_len) != 0) ok = 0;

            if (ok) {
                printf("  RESULT: PASS\n");
                passed++;
            } else {
                printf("  RESULT: FAIL\n");
                failed++;
            }

            free(pt_buf); free(ct_buf); free(out_buf);

        cleanup_vector:
            have_key = have_pt = have_ct = 0;
            key_hex[0] = pt_hex[0] = ct_hex[0] = '\0';
            printf("========================================\n\n");
        }
    }

    fclose(fp);

    printf("\nSUMMARY: total=%d  passed=%d  failed=%d\n", total, passed, failed);
    return (failed == 0) ? 0 : 2;
}
