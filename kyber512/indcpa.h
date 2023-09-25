#ifndef INDCPA_H
#define INDCPA_H

void indcpa_keypair(unsigned char *pk,
                    unsigned char *sk);

void indcpa_enc(unsigned char *c,
                const unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coins);

void indcpa_dec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk);

// additional implementation - oksuman
void add(unsigned char *c, unsigned char*c1, unsigned char* c2);
void shuffle(int16_t *array, int size);
void randomize_poly(unsigned char *r, unsigned char*c, int hwt);

#endif
