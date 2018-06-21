
CXX=g++
CFLAGS=-I.
DEPS = main
OBJ = mbedtls/base64.o mbedtls/md5.o mbedtls/aes.o mbedtls/aesni.o mbedtls/platform_util.o mbedtls/sha1.o mbedtls/entropy.o mbedtls/sha512.o mbedtls/entropy_poll.o mbedtls/timing.o mbedtls/ctr_drbg.o
CFLAGS = -D MBEDTLS_CONFIG_FILE=\"config.h\" -Imbedtls/ -I../ -I.

%.o: %.c $(DEPS)
	$(CXX) -c -o $@ $< $(CFLAGS)

%.o: %.cc $(DEPS)
	$(CXX) -c  -o $@ $< $(CFLAGS)

all: enc dec

enc: encrypt.o $(OBJ)
	$(CXX) -o $@ $^ $(CFLAGS)

dec: decrypt.o $(OBJ)
	$(CXX) -o $@ $^ $(CFLAGS)

clean:
	rm -f enc
	rm -f dec
