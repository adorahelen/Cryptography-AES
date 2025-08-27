CC=gcc
OPENSSL_PATH=$(shell brew --prefix openssl)
CFLAGS=-I$(OPENSSL_PATH)/include
LDFLAGS=-L$(OPENSSL_PATH)/lib -lssl -lcrypto

# 기본 빌드 대상
all:  AES_Lib AES_Pure T_AES_Lib T_AES_Pure  

# kmkimC.c 빌드
# kmkimC: kmkimC.c
# 	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)


# assign.c (OpenSSL 안 쓰는 경우 단순 컴파일)
AES_Lib: AES_v1_lib.c
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

AES_Pure: AES_v2_pure.c
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

T_AES_Lib: Test_ECB128Key_lib.c
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

T_AES_Pure: Test_ECB128Key_pure.c
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

# 불필요한 파일 정리
clean:
	rm -f AES_Lib AES_Pure T_AES_Lib T_AES_Pure