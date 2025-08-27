# AES Implementation and Validation

본 프로젝트는 **AES (Advanced Encryption Standard)** 의 기본 원리를 이해하고,  
직접 구현 및 OpenSSL 라이브러리를 이용하여 검증 테스트를 진행한 내용을 정리한 것입니다.  

---

## 진행 내용

### 1. AES 기본 구현
- **AES-128 ECB 모드**를 기준으로 C언어로 직접 구현
- 주요 구성 요소:
  - SubBytes
  - ShiftRows
  - MixColumns
  - AddRoundKey
  - Key Expansion
- 블록 크기: 16바이트  
- 라운드 수: 10회

### 2. 패딩 처리
- AES는 블록 암호이므로 입력 데이터 길이가 16바이트의 배수여야 함.
- `PKCS#7` 패딩 방식을 적용:
  - 남는 공간을 `padding_length` 값으로 채움
  - 예: `0x04 0x04 0x04 0x04`

### 3. 암호화 모드
- 초기 구현은 단순화를 위해 **ECB 모드** 사용
- 실제 보안 환경에서는 CBC, GCM 등 안전한 모드 권장

### 4. OpenSSL 기반 검증
- OpenSSL AES API (`<openssl/aes.h>`) 활용
- 테스트 벡터 기반 암호화/복호화 결과 검증
- 주요 사용 코드:
  ```c
  AES_set_encrypt_key(key, 128, &enc_key);
  AES_encrypt(in, out, &enc_key);
  ````

* `.rsp` 파일을 이용한 **CAVP (Cryptographic Algorithm Validation Program)** 테스트 벡터 자동 검증 프로그램 작성

### 5. 테스트 벡터 (NIST 기준)

* AES-128 KAT (Known Answer Test) 벡터 활용
* Key, Plaintext, Ciphertext 비교
* 검증 프로그램:

  * 입력: `.rsp` 테스트 벡터 파일
  * 출력: Pass / Fail 결과

---

## 🛠️ 빌드 & 실행 방법

### 1. 기본 AES 구현 빌드

```bash
make, make clean
* Makefile 내부 명령어 수정 필요 
* 실행 : ./aes_basic 
```

### 2. OpenSSL AES 예제 빌드

```bash
동일 
```

### 3. KAT 검증 프로그램

```bash
동일
* 실행 : ./aes_basic nameOfRspfile.rsp
```

---

## 📂 디렉토리 구조

```
.
├── AES_v1_lib.c       # AES-128 ECB 테스트 코드 (라이브러리 사용)
├── AES_v2_pure.c      # AES-128 ECB 테스트 코드 (라이브러리 미사용)
├── ECBVarKey128.rsp   # NIST AES 테스트 벡터 (키 변환 예제)
├── ECBVarTxt128.rsp   # NIST AES 테스트 벡터 (평문 변환 예제)
├── Makefile               # 빌드 파일 
├── Test_ECB128Key_lib.c   # KAT 벡터 자동 검증 프로그램 (라이브러리 사용)
├── Test_ECB128Key_pure.c  # KAT 벡터 자동 검증 프로그램 (라이브러리 미사용)
└── README.md
```

---

## 요약

* AES 내부 구조와 라운드 함수 동작 원리 이해
* 블록 암호에서 패딩이 필요한 이유와 적용 방식 학습
* OpenSSL 라이브러리를 활용한 검증 기법 습득
* CAVP 테스트 벡터 기반의 표준 검증 절차 경험

---

## 추가조사(예정)

* CBC, GCM 모드 추가 구현
* RSA (Rivest-Shamir-Adleman) 와 ECC (Elliptic Curve Cryptography) 비교 및 분석
* SHA 암호 알고리즘의 이론과 구현 방안 
* KAT 방식이 아닌, MCT & MMT 방식의 테스트 벡터 조사 및 적용 

---

## 참고

* NIST. (2001). FIPS PUB 197: Advanced Encryption Standard (AES) 
* NIST. (2016). Cryptographic Algorithm Validation Program (Test Vectors)

---
