LIB = -L./tinycbor/lib
LIB += -L./mbedtls/library

INCLUDE = -I./tinycbor/src
INCLUDE += -I./micro-ecc
INCLUDE += -I./mbedtls/include
INCLUDE += -I./cose-lib/include

INCLUDE += -I./src

SOURCE += micro-ecc/*.c
SOURCE += cose-lib/src/*.c

SOURCE += src/*.c





all: lib-cbor lib-mbedtls main

lib-cbor:
	cd tinycbor/ && $(MAKE) clean && $(MAKE) LDFLAGS='' -j8 lib/libtinycbor.a

lib-mbedtls:
	cd mbedtls/ && $(MAKE) lib

main: 
	mkdir -p build && $(CC) -g -o build/main $(SOURCE) $(LIB) $(INCLUDE) -ltinycbor -lmbedcrypto


clean:
	cd tinycbor && $(MAKE) clean && cd .. && cd mbedtls && $(MAKE) clean && cd .. && rm -rf build