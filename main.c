#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#define DEBUGF 1

#define DEBUG(f) (DEBUGF ? f : (void)0);

#define ROUNDS 2

typedef struct block_t {
  unsigned char n0 : 4;
  unsigned char n1 : 4;
  unsigned char n2 : 4;
  unsigned char n3 : 4;
} __attribute__ ((packed)) block_t;

block_t K0 = {
  .n0 = 0b1100,
  .n1 = 0b0011,
  .n2 = 0b1111,
  .n3 = 0b0000
};

//--------------------------------------------------------
// UTIL
//--------------------------------------------------------

void panic(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  printf("ERROR: ");
  vprintf(fmt, args);
  va_end(args);

  exit(-1);
}

#define bit_print(c, n) ((c >> n) & 1 ? printf("1") : printf("0"))
#define print_nibble(c) for (int _i = 3; _i >= 0; _i--) bit_print(c, _i); printf(" ");

void print_block(block_t *b, size_t len) {
  for (unsigned int i = 0; i < len; i++) {
    printf("(%d) ", i);
    print_nibble(b[i].n0); 
    print_nibble(b[i].n1); 
    print_nibble(b[i].n2); 
    print_nibble(b[i].n3); 
    printf("\n");
  }
}

block_t *to_block(char *msg, size_t *len) {
  *len = strlen(msg);

  if (*len % 2) {
    panic("invalid odd message length: %d\n", len);
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
  unsigned short tr = ((r & 0b10 ? l << 1 : 0) ^ (r & 1 ? l : 0));
  return (tr >= 255 ? tr ^ 0b10011 : tr);
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

block_t *gen_key(block_t *k0, unsigned int r) {
  block_t *res = malloc(r * sizeof(block_t));

  memcpy(res, k0, sizeof(block_t));
  for (unsigned int i = 1; i < r; i++) {
    res[i].n0 = res[i - 1].n0 ^ SUB_TABLE[res[i - 1].n3] ^ (1 << ((i - 1) % 4)); // care
    res[i].n1 = res[i - 1].n1 ^ res[i].n0;
    res[i].n2 = res[i - 1].n2 ^ res[i].n1;
    res[i].n3 = res[i - 1].n3 ^ res[i].n2;
  }

  return res;
}

//--------------------------------------------------------
// DE/ENCRYPT BLOCK
//--------------------------------------------------------

void encrypt(block_t *b, block_t *k, unsigned int r) {
  DEBUG(printf("ENCRYPING:\n"));
  DEBUG(print_block(b, 1));
  DEBUG(printf("KEY:\n"));
  DEBUG(print_block(k, r + 1));
  key_add(b, k);
  DEBUG(printf("KEY ADDITION:\n"));
  DEBUG(print_block(b, 1));
  for (unsigned int i = 1; i < r; i++) {
    nibble_sub(b);
    DEBUG(printf("NIBBLE SUB\n"));
    DEBUG(print_block(b, 1));
    shift_row(b);
    DEBUG(printf("SHIFT ROW\n"));
    DEBUG(print_block(b, 1));
    mix_column(b);
    DEBUG(printf("MIX COLUMN\n"));
    DEBUG(print_block(b, 1));
    key_add(b, k + i);
    DEBUG(printf("KEY ADD\n"));
    DEBUG(print_block(b, 1));
  }
  nibble_sub(b);
  DEBUG(printf("NIBBLE SUB\n"));
  DEBUG(print_block(b, 1));
  shift_row(b);
  DEBUG(printf("SHIFT ROW\n"));
  DEBUG(print_block(b, 1));
  key_add(b, k + r);
  DEBUG(printf("KEY ADDITION:\n"));
  DEBUG(print_block(b, 1));
}

void decrypt(block_t  *b, block_t *k, unsigned int r) {
  DEBUG(printf("DECRYPTING:\n"));
  DEBUG(print_block(b, 1));
  DEBUG(printf("KEY:\n"));
  DEBUG(print_block(k, r + 1));
  key_add(b, k + r);
  DEBUG(printf("KEY ADDITION:\n"));
  DEBUG(print_block(b, 1));
  for (unsigned int i = r - 1; i > 0; i--) {
    nibble_sub_inv(b);
    DEBUG(printf("NIBBLE SUB\n"));
    DEBUG(print_block(b, 1));
    shift_row(b);
    DEBUG(printf("SHIFT ROW\n"));
    DEBUG(print_block(b, 1));
    key_add(b, k + i);
    DEBUG(printf("KEY ADD\n"));
    DEBUG(print_block(b, 1));
    mix_column(b);
    DEBUG(printf("MIX COLUMN\n"));
    DEBUG(print_block(b, 1));
  }
  nibble_sub_inv(b);
  DEBUG(printf("NIBBLE SUB\n"));
  DEBUG(print_block(b, 1));
  shift_row(b);
  DEBUG(printf("SHIFT ROW\n"));
  DEBUG(print_block(b, 1));
  key_add(b, k);
  DEBUG(printf("KEY ADD\n"));
  DEBUG(print_block(b, 1));
}

int main(int argc, char **argv) {

  if (argc <= 2) {
    panic("usage: ./mini_aes (d|e) file\n");
  }

  FILE *in = fopen(argv[2], "rb");

  char *outf = malloc(strlen(argv[2]) + 5);
  memcpy(outf, argv[2], strlen(argv[2]));
  strcat(outf, ".out"); 
  FILE *out = fopen(outf, "wb");

  if (!out || !in) {
    panic("unable to open out/input file: %s", argv[2], outf);
  }

  size_t msg_len;
  fseek(in , 0L , SEEK_END);
  msg_len = ftell(in);
  rewind(in);
  char *msg= malloc(msg_len);
  if (!fread(msg, msg_len, 1, in)) {
    panic("unable to read complete file\n");
  }

  if (msg_len % 2) {
    panic("invalid odd message length: %d\n", msg_len);
  }

  size_t block_len = 0;
  block_t *block = to_block(msg, &block_len);

  // init key 
  block_t *key = gen_key(&K0, ROUNDS + 1);

  if (argv[1][0] == 'e') {
    printf("ENCRYPTING: %s\n", msg);

    for (unsigned int i = 0; i < block_len; i++) {
      encrypt(block + i, key, ROUNDS);
    }

  } else if (argv[1][0] == 'd') {
    printf("DECRYPTING: %s\n", msg);

    for (unsigned int i = 0; i < block_len; i++) {
      decrypt(block + i, key, ROUNDS);
    }

  } else {
    printf("invalid encryption method: %c\n", argv[1][0]);
  }

  char *res = to_str(block, block_len);

  printf("result: %s\n", res);

  if (!fwrite(res, msg_len, 1, out)) {
    panic("unable to write complete output to file\n");
  }

  free(msg);
  free(block);
  free(res);  

  fclose(in);
  fclose(out);

  return 0;
}
