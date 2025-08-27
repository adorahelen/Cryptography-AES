#include <stdio.h>
#include <string.h>

// AES-128의 블록 크기와 키 크기는 16바이트(128비트)
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16
#define AES_ROUNDS 10

// S-Box 및 Rcon 테이블
const unsigned char s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// 키 확장 함수
void key_expansion(const unsigned char *key, unsigned char *w) {
    unsigned char temp[4];
    int i = 0;

    // 초기 라운드 키
    for (i = 0; i < AES_KEY_SIZE; i++) {
        w[i] = key[i];
    }

    // 나머지 라운드 키 생성
    for (i = AES_KEY_SIZE; i < AES_BLOCK_SIZE * (AES_ROUNDS + 1); i += 4) {
        temp[0] = w[i - 4];
        temp[1] = w[i - 3];
        temp[2] = w[i - 2];
        temp[3] = w[i - 1];

        // 라운드 키 생성 로직
        if (i % AES_KEY_SIZE == 0) {
            unsigned char temp_rot[4] = { temp[1], temp[2], temp[3], temp[0] };
            temp[0] = s_box[temp_rot[0]] ^ rcon[i / AES_KEY_SIZE];
            temp[1] = s_box[temp_rot[1]];
            temp[2] = s_box[temp_rot[2]];
            temp[3] = s_box[temp_rot[3]];
        }
        
        w[i + 0] = w[i - AES_KEY_SIZE] ^ temp[0];
        w[i + 1] = w[i - AES_KEY_SIZE + 1] ^ temp[1];
        w[i + 2] = w[i - AES_KEY_SIZE + 2] ^ temp[2];
        w[i + 3] = w[i - AES_KEY_SIZE + 3] ^ temp[3];
    }
}

// SubBytes 함수
void sub_bytes(unsigned char *state) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = s_box[state[i]];
    }
}

// ShiftRows 함수
void shift_rows(unsigned char *state) {
    unsigned char temp[AES_BLOCK_SIZE];

    // 행렬 전치
    unsigned char state_col[4][4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state_col[j][i] = state[i * 4 + j];
        }
    }

    // 0행: 변화 없음
    temp[0] = state_col[0][0]; temp[1] = state_col[0][1]; temp[2] = state_col[0][2]; temp[3] = state_col[0][3];

    // 1행: 왼쪽으로 1바이트 시프트
    temp[4] = state_col[1][1]; temp[5] = state_col[1][2]; temp[6] = state_col[1][3]; temp[7] = state_col[1][0];

    // 2행: 왼쪽으로 2바이트 시프트
    temp[8] = state_col[2][2]; temp[9] = state_col[2][3]; temp[10] = state_col[2][0]; temp[11] = state_col[2][1];

    // 3행: 왼쪽으로 3바이트 시프트
    temp[12] = state_col[3][3]; temp[13] = state_col[3][0]; temp[14] = state_col[3][1]; temp[15] = state_col[3][2];

    // 다시 원래 배열 형식으로
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i * 4 + j] = temp[j * 4 + i];
        }
    }
}

// MixColumns 함수 (갈루아 필드 곱셈)
unsigned char gf_mul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if ((b & 1) == 1) {
            p ^= a;
        }
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80) {
            a ^= 0x1b; // 0x1b는 AES GF(2^8)의 다항식
        }
        b >>= 1;
    }
    return p;
}

void mix_columns(unsigned char *state) {
    unsigned char temp[AES_BLOCK_SIZE];
    
    for (int i = 0; i < 4; i++) {
        temp[i * 4 + 0] = gf_mul(0x02, state[i * 4 + 0]) ^ gf_mul(0x03, state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        temp[i * 4 + 1] = state[i * 4 + 0] ^ gf_mul(0x02, state[i * 4 + 1]) ^ gf_mul(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3];
        temp[i * 4 + 2] = state[i * 4 + 0] ^ state[i * 4 + 1] ^ gf_mul(0x02, state[i * 4 + 2]) ^ gf_mul(0x03, state[i * 4 + 3]);
        temp[i * 4 + 3] = gf_mul(0x03, state[i * 4 + 0]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ gf_mul(0x02, state[i * 4 + 3]);
    }
    memcpy(state, temp, AES_BLOCK_SIZE);
}

// AddRoundKey 함수
void add_round_key(unsigned char *state, const unsigned char *round_key) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= round_key[i];
    }
}

// 단일 블록 암호화 함수
void aes_encrypt_block(unsigned char *block, const unsigned char *round_keys) {
    unsigned char state[AES_BLOCK_SIZE];
    memcpy(state, block, AES_BLOCK_SIZE);

    add_round_key(state, round_keys);

    for (int i = 1; i < AES_ROUNDS; i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + i * AES_BLOCK_SIZE);
    }
    
    // 마지막 라운드는 MixColumns를 수행하지 않습니다.
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + AES_ROUNDS * AES_BLOCK_SIZE);

    memcpy(block, state, AES_BLOCK_SIZE);
}

// PKCS#7 패딩 함수
int pkcs7_padding(unsigned char *data, int data_len, int block_size) {
    int padding_len = block_size - (data_len % block_size);
    memset(data + data_len, (unsigned char)padding_len, padding_len);
    return data_len + padding_len;
}

int main() {
    unsigned char key[AES_KEY_SIZE] = "SeoulTechAESKey1"; // AES-128
    unsigned char plaintext[] = "서울과학기술대학교";
    unsigned char padded_plaintext[128];
    unsigned char ciphertext[128];
    unsigned char round_keys[AES_BLOCK_SIZE * (AES_ROUNDS + 1)];
    
    int plaintext_len = strlen(plaintext);
    int padded_len;

    // 1. 키 확장
    key_expansion(key, round_keys);

    // 2. 평문에 패딩 추가
    memcpy(padded_plaintext, plaintext, plaintext_len);
    padded_len = pkcs7_padding(padded_plaintext, plaintext_len, AES_BLOCK_SIZE);
    
    // 3. 블록 단위 암호화 (ECB 모드)
    for (int i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        aes_encrypt_block(padded_plaintext + i, round_keys);
    }

    // 결과 복사
    memcpy(ciphertext, padded_plaintext, padded_len);
    
    // 4. 결과 출력
    printf("평문 입력 : %s\n", plaintext);
    printf("암호화 과정(패딩 처리된 최종 길이): %d bytes\n", padded_len);
    printf("암호문 (hex): ");
    for (int i = 0; i < padded_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}