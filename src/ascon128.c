#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef unsigned long long u64;
typedef unsigned char u8;

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

typedef struct {
    u64 x[5];
} State;

// Global variables so LIEF can locate them in memory for Python injection
u8 key[16]   = {0};
u8 nonce[16] = {0};
u8 pt[]      = "Hello, ASCON!";
u8 ct[13];
u8 tag[16];

static const u64 RC[12] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

static void sbox(State *s) {
    u64 t[5];
    s->x[0] ^= s->x[4]; s->x[4] ^= s->x[3]; s->x[2] ^= s->x[1];
    t[0] = s->x[0]; t[1] = s->x[1]; t[2] = s->x[2]; t[3] = s->x[3]; t[4] = s->x[4];
    t[0] = ~t[0]; t[1] = ~t[1]; t[2] = ~t[2]; t[3] = ~t[3]; t[4] = ~t[4];
    t[0] &= s->x[1]; t[1] &= s->x[2]; t[2] &= s->x[3]; t[3] &= s->x[4]; t[4] &= s->x[0];
    s->x[0] ^= t[1]; s->x[1] ^= t[2]; s->x[2] ^= t[3]; s->x[3] ^= t[4]; s->x[4] ^= t[0];
    s->x[1] ^= s->x[0]; s->x[0] ^= s->x[4]; s->x[3] ^= s->x[2]; s->x[2] = ~s->x[2];
}

static void linear_layer(State *s) {
    s->x[0] ^= ROTR(s->x[0], 19) ^ ROTR(s->x[0], 28);
    s->x[1] ^= ROTR(s->x[1], 61) ^ ROTR(s->x[1], 39);
    s->x[2] ^= ROTR(s->x[2],  1) ^ ROTR(s->x[2],  6);
    s->x[3] ^= ROTR(s->x[3], 10) ^ ROTR(s->x[3], 17);
    s->x[4] ^= ROTR(s->x[4],  7) ^ ROTR(s->x[4], 41);
}

static void permute(State *s, int rounds) {
    int start = 12 - rounds;
    for (int i = start; i < 12; i++) {
        s->x[2] ^= RC[i];
        sbox(s);
        linear_layer(s);
    }
}

static u64 bytes_to_u64(const u8 *b) {
    u64 v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

static void u64_to_bytes(u64 v, u8 *b) {
    for (int i = 7; i >= 0; i--) { b[i] = v & 0xff; v >>= 8; }
}

void ascon128_encrypt(
    const u8 key[16], const u8 nonce[16],
    const u8 *ad, size_t adlen,
    const u8 *pt, size_t ptlen,
    u8 *ct, u8 tag[16]
) {
    State s;
    s.x[0] = 0x80400c0600000000ULL;
    s.x[1] = bytes_to_u64(key);
    s.x[2] = bytes_to_u64(key + 8);
    s.x[3] = bytes_to_u64(nonce);
    s.x[4] = bytes_to_u64(nonce + 8);

    permute(&s, 12);

    s.x[3] ^= bytes_to_u64(key);
    s.x[4] ^= bytes_to_u64(key + 8);

    while (adlen >= 8) {
        s.x[0] ^= bytes_to_u64(ad);
        permute(&s, 6);
        ad += 8; adlen -= 8;
    }
    u8 padad[8] = {0};
    memcpy(padad, ad, adlen);
    padad[adlen] = 0x80;
    s.x[0] ^= bytes_to_u64(padad);
    permute(&s, 6);
    s.x[4] ^= 1;

    const u8 *p = pt;
    u8 *c = ct;
    size_t rem = ptlen;
    while (rem >= 8) {
        s.x[0] ^= bytes_to_u64(p);
        u64_to_bytes(s.x[0], c);
        permute(&s, 6);
        p += 8; c += 8; rem -= 8;
    }
    u8 padpt[8] = {0};
    memcpy(padpt, p, rem);
    padpt[rem] = 0x80;
    s.x[0] ^= bytes_to_u64(padpt);
    u8 padct[8];
    u64_to_bytes(s.x[0], padct);
    memcpy(c, padct, rem);

    s.x[1] ^= bytes_to_u64(key);
    s.x[2] ^= bytes_to_u64(key + 8);
    permute(&s, 12);
    s.x[3] ^= bytes_to_u64(key);
    s.x[4] ^= bytes_to_u64(key + 8);

    u64_to_bytes(s.x[3], tag);
    u64_to_bytes(s.x[4], tag + 8);
}

int main(void) {
    ascon128_encrypt(key, nonce, NULL, 0, pt, 13, ct, tag);
    return 0;
}
