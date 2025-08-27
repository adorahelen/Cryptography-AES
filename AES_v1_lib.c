#include <openssl/aes.h>
#include <string.h>
#include <stdio.h>

// PKCS#7 패딩 함수
int pkcs7_padding(unsigned char *data, int data_len, int block_size) {
    int padding_len = block_size - (data_len % block_size);
    memset(data + data_len, (unsigned char)padding_len, padding_len);
    return data_len + padding_len;
}

int main() {
    unsigned char key[16] = "SeoulTechAESKey1"; // AES-128
    unsigned char plaintext[] = "서울과학기술대학교";
    unsigned char padded_plaintext[128];
    unsigned char ciphertext[128];
    
    AES_KEY enc_key, dec_key;
    int plaintext_len = strlen(plaintext);
    int padded_len;

    // 키 설정
    AES_set_encrypt_key(key, 128, &enc_key);

    // 1. 평문에 패딩 추가
    memcpy(padded_plaintext, plaintext, plaintext_len);
    padded_len = pkcs7_padding(padded_plaintext, plaintext_len, AES_BLOCK_SIZE);

    // 2. 블록 단위 암호화 (ECB 모드)
    for (int i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        AES_encrypt(padded_plaintext + i, ciphertext + i, &enc_key);
    }
    
    // 3. 결과 출력
    printf("평문 입력 : %s\n", plaintext);
    printf("암호화 과정(패딩 처리된 최종 길이): %d bytes\n", padded_len);
    printf("암호문 (hex): ");
    for (int i = 0; i < padded_len; i++) {
        printf("%02x", ciphertext[i]);
    }

    return 0;
}