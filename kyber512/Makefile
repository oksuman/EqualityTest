CC = /usr/bin/gcc
LDFLAGS = -lcrypto

SOURCES = cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c rng.c verify.c symmetric-fips202.c EqualityTest_kyber.c
HEADERS = api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h

EqualityTest_kyber: $(HEADERS) $(SOURCES)
	$(CC) -o $@ $(filter-out PQCgenKAT_kem.c, $(SOURCES)) $(LDFLAGS)

.PHONY: clean

clean:
	-rm EqualityTest_kyber
