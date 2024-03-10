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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "argon2.h"


#define HASHLEN 32
#define SALTLEN 16
#define PWD "password1"
#define FIFO_NAME "/tmp/pam_fifo1"


/* PAM entry point for session creation */
// gets called if the user successfully authenticates
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // create master key
    // start FUSE
    printf("session starting\n");
    return(PAM_IGNORE);
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // memory scrubbing of master key and main key
    // stop FUSE
    printf("session ending\n");
    return(PAM_IGNORE);
}

/* PAM entry point for accounting */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return(PAM_IGNORE);
}

/* PAM entry point for authentication verification */
// gets called in a situation where the user has to put in their PW
// also runs this function, when user PW is wrong
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("authentication starting\n");

    printf("uid: %d\n", getuid());
    const char * password = NULL;
    // const char * user = NULL;
    FILE * file = fopen("/home/foda-se/gitlab/transparent_enc_ba/testfile.txt", "a+");
    if( file == NULL) {
            return(PAM_IGNORE);
    }

    int auth_ret = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    printf("auth_ret=%d\n",auth_ret);

    // fwrite(password, strlen(password), 1,file);
    uint8_t hash1[HASHLEN];

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint8_t *pwd = (uint8_t *)strdup(password);
    uint32_t pwdlen = strlen((char *)password);

    uint32_t t_cost = 2;            // 2-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes
    
    // high-level API
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);
    fwrite(hash1, HASHLEN, 1,file);

    for( int i=0; i<HASHLEN; ++i ) printf( "%02x ", hash1[i] ); 
    printf( "\n" );

    // messaging FUSE
    // mkfifo(FIFO_NAME, 0660);
    // if(mkfifo(FIFO_NAME, 0660) == -1) {
    //   perror("error creating fifo");
    //   exit(EXIT_FAILURE);
    // }


    // start fuse

    // int pid = fork();
    // if (pid == -1) {
    //   perror("fork error");
    //   return PAM_IGNORE;
    // } 
    // else if (pid == 0) {
    //   printf("child starting FUSE\n");

    //   execl("/home/foda-se/gitlab/transparent_enc_ba/user_fuse/testfuse", "-f", "/home/mountpoint", NULL);
    //   perror("execl");
    // }

    // int fifo_fd = open(FIFO_NAME, O_WRONLY);
    // if (fifo_fd < 0) {
    //   perror("error opening pipe");
    //   exit(EXIT_FAILURE);
    // }

    // ssize_t n = write(fifo_fd, hash1, HASHLEN);
    // printf("wrote %lu bytes\n",n);
    // if (n < 0 ) {
    //   perror("error reading key from pipe");
    //   exit(EXIT_FAILURE);
    // }

    // printf("sent message(hex): %hhn\n",hash1);

    // close(fifo_fd);

    free(pwd);

    printf("euid: %d\n", (int)geteuid());
    printf("uid: %d\n", (int)getuid());

    fclose(file);
    printf("authentication ending\n");
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
    // get old PW
    // get new PW
    // go over every File in FUSE
        // decrypt each with old PW
        // encrypt each with new PW
    return(PAM_IGNORE);
}
