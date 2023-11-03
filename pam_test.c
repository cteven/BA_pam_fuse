/* Define which PAM interfaces we provide */
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "argon2.h"


#define HASHLEN 32
#define SALTLEN 16
#define PWD "password1"

/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return(PAM_IGNORE);
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return(PAM_IGNORE);
}

/* PAM entry point for accounting */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return(PAM_IGNORE);
}

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char * password = NULL;
    FILE * file = fopen("/home/steven/github/transparent_encryption/testfile.txt", "a+");
    if( file == NULL) {
            return(PAM_IGNORE);
    }
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

    // fwrite(password, strlen(password), 1,file);

    uint8_t hash1[HASHLEN];

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint8_t *pwd = (uint8_t *)strdup(PWD);
    uint32_t pwdlen = strlen((char *)pwd);

    uint32_t t_cost = 2;            // 2-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes
    
    // high-level API
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, strlen(pwd), salt, SALTLEN, hash1, HASHLEN);
    fwrite(hash1, HASHLEN, 1,file);

    for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash1[i] ); printf( "\n" );

    free(pwd);

    fclose(file);
    return(PAM_IGNORE);
}

/*
   PAM entry point for setting user credentials (that is, to actually
   establish the authenticated user's credentials to the service provider)
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return(PAM_IGNORE);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return(PAM_IGNORE);
}
