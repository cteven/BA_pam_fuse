#ifndef _ENC_UTILS_
#define _ENC_UTILS_

#include <sodium.h>


int encrypt_file(const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

int decrypt_file(const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);


#endif 