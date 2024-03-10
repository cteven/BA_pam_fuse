#include "enc_utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define CHUNK_SIZE 4096

int encrypt_file(const char *target_file, const char *source_file,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
  unsigned char  buf_in[CHUNK_SIZE];
  unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state st;
  FILE          *fp_t, *fp_s;
  unsigned long long out_len;
  size_t         rlen;
  int            eof;
  unsigned char  tag;
  puts("0");
  fp_s = fopen(source_file, "r");
  if(fp_s == NULL) {
    printf("error opening source file, error code %d\n", errno);
    return -errno;
  }
  fp_t = fopen(target_file, "w");
  if(fp_t == NULL) {
    printf("error opening target file, error code %d\n", errno);
    return -errno;
  }
  printf("opened files\n");
  crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
  fwrite(header, 1, sizeof header, fp_t);
  do {
    rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
    eof = feof(fp_s);
    tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
    crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
                                                NULL, 0, tag);
    fwrite(buf_out, 1, (size_t) out_len, fp_t);
  } while (! eof);
  fclose(fp_t);
  fclose(fp_s);
  return 0;
}

int decrypt_file(const char *target_file, const char *source_file,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE          *fp_t, *fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = 0;
    unsigned char  tag;
    printf("source:%s\ntarget:%s\n",source_file,target_file);
    fp_s = fopen(source_file, "r");
    if(fp_s == NULL) {
      printf("error opening source file, error code %d\n", errno);
      return -errno;
    }
    fp_t = fopen(target_file, "w");
    if(fp_t == NULL) {
      printf("error opening target file, error code %d\n", errno);
      return -errno;
    }
    fread(header, 1, sizeof header, fp_s);
  puts("1");
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
      /* incomplete header */
      ret = -1;
    }
  puts("2");
    if (ret != -1) {
      do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
      printf("eof: %d\n",eof);
      puts("3");
        if ((eof == 1) && (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0)) {
          /* corrupted chunk */
          ret = -1;
          break;
        }
        puts("4");
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
          if (!eof) {
            /* end of stream reached before the end of the file */
            ret = -1;
            break;
          }
        } /* not the final chunk yet */ 
        else if (eof) {            
          /* end of file reached before the end of the stream */
          ret = -1;
          break;
        }
        puts("5");
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
        puts("6");
      } while (!eof);
    }
    
  puts("7");
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

