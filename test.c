#include "argon2.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HASHLEN 32
#define SALTLEN 16
#define PWD "password"
#define CHUNK_SIZE 4096

static int
encrypt(const char *target_file, const char *source_file,
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

    fp_s = fopen(source_file, "r");
    fp_t = fopen(target_file, "w");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        printf("rlen %lu\n",rlen);
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

static int
decrypt(const char *target_file, const char *source_file,
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
    int            ret = -1;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        printf("eof: %d\n",eof);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            if (! eof) {
                goto ret; /* end of stream reached before the end of the file */
            }
        } else { /* not the final chunk yet */
            if (eof) {
                goto ret; /* end of file reached before the end of the stream */
            }
        }
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
    } while (! eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

int main() {
  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  if (sodium_init() != 0) {
    return 1;
  }
  crypto_secretstream_xchacha20poly1305_keygen(key);
  if (encrypt("/home/foda-se/gitlab/transparent_enc_ba/encryptiontest/encrypted.txt", "/home/foda-se/gitlab/transparent_enc_ba/encryptiontest/original.txt", key) != 0) {
    return 1;
  }
  if (decrypt("/home/foda-se/gitlab/transparent_enc_ba/encryptiontest/decrypted.txt", "/home/foda-se/gitlab/transparent_enc_ba/encryptiontest/encrypted.txt", key) != 0) {
    return 1;
  }
  return 0;
}

// int main()
// {




  // const char * password = "password1";
  // FILE * file = fopen("/home/foda-se/testfile.txt", "a+");
  // if( file == NULL) {
  //         return(1);
  // }
  
  // fwrite(password, strlen(password), 1,file);

  // uint8_t hash1[HASHLEN];

  // uint8_t salt[SALTLEN];
  // memset( salt, 0x00, SALTLEN );

  // uint8_t *pwd = (uint8_t *)strdup(PWD);
  // uint32_t pwdlen = strlen((char *)pwd);

  // uint32_t t_cost = 2;            // 2-pass computation
  // uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
  // uint32_t parallelism = 1;       // number of threads and lanes
  
  // // high-level API
  // argon2i_hash_raw(t_cost, m_cost, parallelism, password, strlen(password), salt, SALTLEN, hash1, HASHLEN);
  // for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash1[i] ); printf( "\n" );

  // free(pwd);

  // fclose(file);

//     return 0;
// }