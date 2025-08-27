// aes_kat_tester_fixed.c
// Compile: cc aes_kat_tester_fixed.c -o aes_kat_tester_fixed -lcrypto
// Usage: ./aes_kat_tester_fixed <rsp_file>
// Returns 0 if all pass, 2 if any fail, 1 on error.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <openssl/aes.h>

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

// hex (ascii) -> bytes. returns number of bytes or -1 if invalid
static int hex2bin_len(const char *hex, uint8_t *out, size_t out_max) {
    if (!hex || !out) return -1;
    // skip spaces inside string
    size_t hexchars = 0;
    for (const char *p = hex; *p; ++p) if (!isspace((unsigned char)*p)) hexchars++;
    if (hexchars % 2 != 0) return -1;
    size_t bytes = hexchars / 2;
    if (bytes > out_max) return -1;
    // parse
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

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <rsp_file>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("fopen"); return 1; }

    char raw[1024];
    char key_hex[512] = {0}, pt_hex[4096] = {0}, ct_hex[4096] = {0};
    int have_key = 0, have_pt = 0, have_ct = 0;
    int total = 0, passed = 0, failed = 0;
    int current_count = -1;

    while (fgets(raw, sizeof(raw), fp)) {
        // normalize line
        rstrip(raw);
        char *line = raw;
        lstrip_inplace(&line);
        if (line[0] == '\0') continue;
        if (line[0] == '#') continue;
        if (line[0] == '[') {
            // section header: [ENCRYPT], [DECRYPT], ignore
            printf("DEBUG: Section=%s\n", line);
            continue;
        }

        // find '='
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = line; char *v = eq + 1;
        rstrip(k); lstrip_inplace(&k);
        rstrip(v); lstrip_inplace(&v);

        // compare keys ignoring case
        if (strcasecmp(k, "COUNT") == 0) {
            // start new vector; we may or may not want to reset previous fields
            // if previous vector was incomplete, just discard
            current_count = atoi(v);
            have_key = have_pt = have_ct = 0;
            key_hex[0] = pt_hex[0] = ct_hex[0] = '\0';
            // note: we don't increment total here; only when we complete a vector
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
            // ignore other fields (IV, COUNT repeated, etc.)
            continue;
        }

        // if we have full triple, process
        if (have_key && have_pt && have_ct) {
            total++;
            printf("========================================\n");
            printf("VECTOR COUNT=%d (vector #%d)\n", current_count, total);

            // convert key (max 32 bytes)
            uint8_t key_buf[32];
            int key_bytes = hex2bin_len(key_hex, key_buf, sizeof(key_buf));
            if (key_bytes <= 0) {
                printf("ERROR: invalid KEY hex (len=%ld) -> '%s'\n", strlen(key_hex), key_hex);
                failed++;
                goto cleanup_vector;
            }
            // convert plaintext & ciphertext (can be multi-block)
            // determine pt bytes
            // allocate dynamically for arbitrary size (but reasonable upper limit)
            int pt_bytes = 0, ct_bytes = 0;
            // compute lengths and allocate
            size_t pt_hex_len = strlen(pt_hex);
            size_t ct_hex_len = strlen(ct_hex);

            // quick empty-check
            if (pt_hex_len == 0 || ct_hex_len == 0) {
                printf("ERROR: empty PT or CT\n");
                failed++;
                goto cleanup_vector;
            }

            // max allowed blocks (let's cap to 1024 blocks to avoid insane allocations)
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

            pt_bytes = hex2bin_len(pt_hex, pt_buf, pt_bytes_max);
            ct_bytes = hex2bin_len(ct_hex, ct_buf, ct_bytes_max);
            if (pt_bytes <= 0 || ct_bytes <= 0) {
                printf("ERROR: invalid PT/CT hex\n");
                free(pt_buf); free(ct_buf);
                failed++;
                goto cleanup_vector;
            }

            if (pt_bytes != ct_bytes) {
                printf("WARNING: PT and CT lengths differ (%d vs %d). Will compare up to min length.\n", pt_bytes, ct_bytes);
            }
            // ensure block multiple of 16 for AES ECB processing
            if ((pt_bytes % AES_BLOCK_SIZE) != 0) {
                printf("ERROR: plaintext length %d is not multiple of AES block size\n", pt_bytes);
                free(pt_buf); free(ct_buf);
                failed++;
                goto cleanup_vector;
            }

            // prepare result buffer
            uint8_t *out_buf = malloc(pt_bytes);
            if (!out_buf) { perror("malloc"); free(pt_buf); free(ct_buf); failed++; goto cleanup_vector; }
            memset(out_buf, 0, pt_bytes);

            // set AES key (key_bytes*8 = bits)
            int key_bits = key_bytes * 8;
            AES_KEY aes_key;
            if (!(key_bits == 128 || key_bits == 192 || key_bits == 256)) {
                printf("ERROR: unsupported key size %d bits\n", key_bits);
                free(pt_buf); free(ct_buf); free(out_buf); failed++; goto cleanup_vector;
            }
            if (AES_set_encrypt_key(key_buf, key_bits, &aes_key) != 0) {
                printf("ERROR: AES_set_encrypt_key failed\n");
                free(pt_buf); free(ct_buf); free(out_buf); failed++; goto cleanup_vector;
            }

            // compute AES-ECB encrypt block by block
            for (int i = 0; i < pt_bytes; i += AES_BLOCK_SIZE) {
                AES_ecb_encrypt(pt_buf + i, out_buf + i, &aes_key, AES_ENCRYPT);
            }

            // print inputs and outputs
            print_hex_label("  KEY", key_buf, key_bytes);
            print_hex_label("  PLAINTEXT", pt_buf, pt_bytes);
            print_hex_label("  EXPECTED CIPHERTEXT", ct_buf, ct_bytes);
            print_hex_label("  CALCULATED CIPHERTEXT", out_buf, pt_bytes);

            // compare
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
            // reset flags for next vector
            have_key = have_pt = have_ct = 0;
            key_hex[0] = pt_hex[0] = ct_hex[0] = '\0';
            printf("========================================\n\n");
        } // if have all
    } // while fgets

    fclose(fp);

    printf("\nSUMMARY: total=%d  passed=%d  failed=%d\n", total, passed, failed);
    return (failed == 0) ? 0 : 2;
}
