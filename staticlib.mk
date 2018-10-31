TARGET = ndn-standalone.a
TARGET_DIR = build

SRC_FILES += \
encode/data.c \
encode/decoder.c \
encode/encoder.c \
encode/interest.c \
encode/metainfo.c \
encode/name-component.c \
encode/name.c \
encode/signature.c \
security/sign-verify.c \
security/micro-ecc/uECC.c \
security/tinycrypt/aes_decrypt.c \
security/tinycrypt/aes_encrypt.c \
security/tinycrypt/cbc_mode.c \
security/tinycrypt/ccm_mode.c \
security/tinycrypt/cmac_mode.c \
security/tinycrypt/ctr_mode.c \
security/tinycrypt/ctr_prng.c \
security/tinycrypt/ecc_dh.c \
security/tinycrypt/ecc_dsa.c \
security/tinycrypt/ecc_platform_specific.c \
security/tinycrypt/ecc.c \
security/tinycrypt/hmac_prng.c \
security/tinycrypt/hmac.c \
security/tinycrypt/sha256.c \
security/tinycrypt/utils.c \

OBJECT_FILES = $(SRC_FILES:.c=.o)

INCUDE_FOLDERS += \
-Iencode \
-Isecurity \

CLFAGS = -Wall

CC = arm-none-eabi-gcc

all: $(TARGET)

$(TARGET): $(OBJECT_FILES)
	ar rcs $@ $^

%.o : %.c
	echo "now compile $<"
	$(CC) -c $(CFLAGS) $(INCUDE_FOLDERS) $< -o $@
