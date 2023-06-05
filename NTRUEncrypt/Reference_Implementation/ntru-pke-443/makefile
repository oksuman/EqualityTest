CC = gcc
CXX = g++
CFLAGS = -I/usr/include -O3 -g3 -Wall -c -fmessage-length=0 -MMD -MP
LDFLAGS = -lm -lcrypto

SRCS = EqualityTest_NTRU.c encrypt.c packing.c param.c ../common/rng.c poly.c ../common/crypto_hash_sha512.c ../common/crypto_stream.c ../common/fastrandombytes.c ../common/shred.c NTRUEncrypt.c
COBJS = NTRUEncrypt.o
OBJS = $(SRCS:.c=.o) $(COBJS)
EXECUTABLE = ntruTest

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: C Linker'
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo 'Finished building target: $@'
	@echo ' '

%.o: %.c
	@echo 'Building file: $<'
	@echo 'Invoking: C Compiler'
	$(CC) $(CFLAGS) -o $@ $<
	@echo 'Finished building: $<'
	@echo ' '

clean:
	@echo 'Cleaning...'
	rm -f $(OBJS) $(EXECUTABLE)
	@echo 'Cleaned.'
