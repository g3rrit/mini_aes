#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

typedef struct block_t {
  unsigned char n0 : 4;
  unsigned char n1 : 4;
  unsigned char n2 : 4;
  unsigned char n3 : 4;
} __attribute__ ((packed)) block_t;


//--------------------------------------------------------
// UTIL
//--------------------------------------------------------

inline void error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  printf("ERROR: ");
  vprintf(fmt, args);
  va_end(args);

  exit(-1);
}

block_t *to_block(char *msg, size_t *len) {
  *len = strlen(msg);

  if (*len % 2) {
    error("invalid odd message length: %d\n", len);
  }

  *len /= 2;

  block_t *res = malloc(*len);
  for (size_t i = 0; i < *len; i++) {
    unsigned char c0 = msg[i * 2];
    unsigned char c1 = msg[(i * 2) + 1];
    res[i].n0 = c0 >> 4;
    res[i].n1 = c0 & 0xf; 
    res[i].n2 = c1 >> 4;
    res[i].n3 = c1 & 0xf;
  }

  return res;
}

char *to_str(block_t *b, size_t len) {
  char *res = malloc(len * 2 + 1);

  for (size_t i = 0; i < len; i++) {
    res[2 * i] = b[i].n0 << 4;
    res[2 * i] |= b[i].n1;
    res[(2 * i) + 1] = b[i].n2 << 4;
    res[(2 * i) + 1] |= b[i].n3;
  }

  res[len * 2 + 1] = 0;

  return res;
}

unsigned char add(unsigned char l, unsigned char r) {
  return l ^ r;
}

unsigned char mul(unsigned char l, unsigned char r) {
  return ((l & 0b10 ? r << 1 : 0) ^ (l & 1 ? r : 0)) ^ 0b10011;
}

//--------------------------------------------------------
//--------------------------------------------------------

//--------------------------------------------------------
// NIBBLE SUBSTITUTION
//--------------------------------------------------------

unsigned char const SUB_TABLE[] = {
  0b1110,
  0b0100,
  0b1101,
  0b0001,
  0b0010,
  0b1111,
  0b1011,
  0b1000,

  0b0011,
  0b1010,
  0b0110,
  0b1100,
  0b0101,
  0b1001,
  0b0000,
  0b0111,
};

unsigned char const SUB_TABLE_INV[] = {
  0b1110,
  0b0011,
  0b0100,
  0b1000,
  0b0001,
  0b1100,
  0b1010,
  0b1111,

  0b0111,
  0b1101,
  0b1001,
  0b0110,
  0b1011,
  0b0010,
  0b0000,
  0b0101,
};

void nibble_sub(block_t *b) {
  b->n0 = SUB_TABLE[b->n0];
  b->n1 = SUB_TABLE[b->n1];
  b->n2 = SUB_TABLE[b->n2];
  b->n3 = SUB_TABLE[b->n3];
}

void nibble_sub_inv(block_t *b) {
  b->n0 = SUB_TABLE_INV[b->n0];
  b->n1 = SUB_TABLE_INV[b->n1];
  b->n2 = SUB_TABLE_INV[b->n2];
  b->n3 = SUB_TABLE_INV[b->n3];
}

//--------------------------------------------------------
// SHIFT ROW
//--------------------------------------------------------

void shift_row(block_t *b) {
  unsigned char t = b->n1;
  b->n1 = b->n3;
  b->n3 = t;
}

//--------------------------------------------------------
// MIX COLUMN
//--------------------------------------------------------

block_t const MCM = {
  .n0 = 0b0011,
  .n1 = 0b0010,
  .n2 = 0b0010,
  .n3 = 0b0011
};

void mix_column(block_t *b) {
  unsigned char r0 = add(mul(b->n0, MCM.n0), mul(b->n1, MCM.n2));
  unsigned char r1 = add(mul(b->n0, MCM.n1), mul(b->n1, MCM.n3));
  unsigned char r2 = add(mul(b->n2, MCM.n0), mul(b->n3, MCM.n2));
  unsigned char r3 = add(mul(b->n2, MCM.n1), mul(b->n3, MCM.n3));
  b->n0 = r0;
  b->n1 = r1;
  b->n2 = r2;
  b->n3 = r3;
}

//--------------------------------------------------------
// KEY ADDITION
//--------------------------------------------------------

void key_add(block_t *b, block_t *k) {
  b->n0 ^= k->n0;
  b->n1 ^= k->n1;
  b->n2 ^= k->n2;
  b->n3 ^= k->n3;
}

//--------------------------------------------------------
// GENERATE NEXT KEY
//--------------------------------------------------------

block_t K0 = {
  .n0 = 0b1000,
  .n1 = 0b1010,
  .n2 = 0b0011,
  .n3 = 0b1010
};

block_t K;

void next_key(block_t *k, unsigned int r) {
  block_t ck;
  memcpy(&ck, k, sizeof(block_t));
  k->n0 = ck.n0 ^ SUB_TABLE[ck.n3] ^ (1 << (r % 4)); // care
  k->n1 = ck.n1 ^ k->n0;
  k->n2 = ck.n2 ^ k->n1;
  k->n3 = ck.n3 ^ k->n2;
}

void next_key_inv(block_t *k, unsigned int r) {
  block_t ck;
  memcpy(&ck, k, sizeof(block_t));
  k->n0 = ck.n0 ^ SUB_TABLE_INV[ck.n3] ^ (1 << (r % 4)); // care
  k->n1 = ck.n1 ^ k->n0;
  k->n2 = ck.n2 ^ k->n1;
  k->n3 = ck.n3 ^ k->n2;
}

//--------------------------------------------------------
// DE/ENCRYPT BLOCK
//--------------------------------------------------------

void encrypt(block_t *b, block_t *k, unsigned int r) {
  key_add(b, k);
  for (unsigned int i = 1; i < r; i++) {
    next_key(k, i);
    nibble_sub(b);
    shift_row(b);
    mix_column(b);
    key_add(b, k);
  }
  next_key(k, r);
  nibble_sub(b);
  shift_row(b);
  key_add(b, k);
}

void decrypt(block_t  *b, block_t *k, unsigned int r) {
  key_add(b, k);
  for (unsigned int i = 1; i < r; i++) {
    next_key_inv(k, i);
    shift_row(b);
    nibble_sub_inv(b);
    mix_column(b);
    key_add(b, k);
  }
  next_key_inv(k, r);
  shift_row(b);
  nibble_sub_inv(b);
  key_add(b, k);

}

int main(int argc, char **argv) {

  if (argc <= 1) {
    error("usage: ./mini_aes message\n");
  }

  size_t msg_len = strlen(argv[1]);
  if (msg_len % 2) {
    error("invalid odd message length: %d\n", msg_len);
  }

  printf("encrypting: %s\n", argv[1]);

  size_t block_len = 0;
  block_t *block = to_block(argv[1], &block_len);

  // init key 
  memcpy(&K, &K0, sizeof(block_t));

#define ROUNDS 2 // needs to be mod 4
  for (unsigned int i = 0; i < block_len; i++) {
    encrypt(block + i, &K, ROUNDS);
  }

  memcpy(&K, &K0, sizeof(block_t));
  for (unsigned int i = 0; i < block_len; i++) {
    decrypt(block + i, &K, ROUNDS);
  }

  char *cipher = to_str(block, block_len);

  printf("cipher: %s\n", cipher);

  free(block);
  free(cipher);  


  return 0;
}
