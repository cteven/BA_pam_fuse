#include "enc_utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#define CHUNK_SIZE 4096

int encrypt_file(const char *source_file, const char *target_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
  unsigned char  buf_plaintext[CHUNK_SIZE];
  unsigned char  buf_encrypted[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state state;
  FILE          *f_target_file, *f_source_file;
  unsigned long long dec_len;
  size_t         rlen;
  int            eof;
  unsigned char  tag = 0;

  f_source_file = fopen(source_file, "r");
  if(f_source_file == NULL) {
    fprintf(stderr, "error opening source file, error code %d\n", errno);
    return -errno;
  }
  f_target_file = fopen(target_file, "w");
  if(f_target_file == NULL) {
    fprintf(stderr, "error opening target file, error code %d\n", errno);
    fclose(f_source_file);
    return -errno;
  }

  crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
  fwrite(header, 1, sizeof(header), f_target_file);

  do {
    rlen = fread(buf_plaintext, 1, sizeof(buf_plaintext), f_source_file);
    eof = feof(f_source_file);
    if(eof) {
      tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    }
    if (crypto_secretstream_xchacha20poly1305_push(&state, buf_encrypted, &dec_len, buf_plaintext, rlen, NULL, 0, tag)) {
      fprintf(stderr, "error encrypting file, error code %d\n", errno);
      unlink(target_file);
      return -errno;
    }

    fwrite(buf_encrypted, 1, (size_t) dec_len, f_target_file);
  } while (!eof);

  fclose(f_target_file);
  fclose(f_source_file);

  return 0;
}

int decrypt_file(const char *source_file, const char *target_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_encrypted[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_plaintext[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE          *f_target_file, *f_source_file;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = 0;
    unsigned char  tag;

    f_source_file = fopen(source_file, "r");
    if(f_source_file == NULL) {
      fprintf(stderr, "error opening source file, error code %d\n", errno);
      return -errno;
    }
    f_target_file = fopen(target_file, "w");
    if(f_target_file == NULL) {
      fprintf(stderr, "error opening target file, error code %d\n", errno);
      fclose(f_source_file);
      return -errno;
    }
    fread(header, 1, sizeof(header), f_source_file);

    if(crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
      ret = -1;
    }

    if(ret != -1) {
      do {
        rlen = fread(buf_encrypted, 1, sizeof(buf_encrypted), f_source_file);
        eof = feof(f_source_file);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_plaintext, &out_len, &tag, buf_encrypted, rlen, NULL, 0) != 0) {
          ret = -1;
          break;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
          if (!eof) {
            ret = -1;
            break;
          }
        }
        else if(eof) {            
          ret = -1;
          break;
        }
        fwrite(buf_plaintext, 1, (size_t) out_len, f_target_file);
      } while (!eof);
    }
    
    fclose(f_target_file);
    fclose(f_source_file);

    return ret;
}

