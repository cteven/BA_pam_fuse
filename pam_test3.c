#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <stdio.h> 

#include <string.h> 
#include <stdlib.h> 

#include "argon2.h"

#define HASHLEN 32
#define SALTLEN 16

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  printf("authentication starting\n");

  const char * password = NULL;

  if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL) != PAM_SUCCESS) {
    fprintf(stderr ,"Error Authenticating User");
    return PAM_IGNORE;
  }

  uint8_t hash[HASHLEN];

  uint8_t salt[SALTLEN];
  //memset( salt, 0x00, SALTLEN );
  salt
  uint8_t *pwd = (uint8_t *)strdup(password);
  uint32_t pwdlen = strlen(password);

  uint32_t t_cost = 1;            // 2-pass computation
  uint32_t m_cost = 100;      // 64 mebibytes memory usage
  uint32_t parallelism = 1;       // number of threads and lanes

  argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash, HASHLEN);

  for( int i=0; i<HASHLEN; ++i ) 
      printf( "%02x", hash[i] ); 
  printf( "\n" );

  explicit_bzero(pwd, pwdlen);

  free(pwd);

  printf("authentication ending\n");

  return(PAM_IGNORE);
}