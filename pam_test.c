/* Define which PAM interfaces we provide */
#define PAM_SM_AUTH
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
#include <signal.h>
#include <pwd.h>
#include <limits.h>
#include <errno.h>

#include "argon2.h"
#include <sodium.h>


#define HASHLEN crypto_secretstream_xchacha20poly1305_KEYBYTES
#define SALTLEN 16
#define BUFLEN 32

static uint8_t hash[HASHLEN];

// can be called to overwrite the hash before the PAM Module is ending
void exit_pam(char * msg) {
  fprintf(stderr, "error: %s", msg);
  explicit_bzero(hash, HASHLEN);
}

/* PAM entry point for authentication verification */
// gets called in a situation where the user has to put in their PW
// also runs this function, when user PW is wrong
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  printf("authentication starting\n");

  struct passwd *pw;
  const char *user;
  if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS)
  {
      exit_pam("failed to get username\n");
      return PAM_IGNORE;
  }
  if ((pw = getpwnam(user)) == NULL)
  {
      exit_pam("couldn't find username\n");
      return PAM_IGNORE;
  }
  if (strcmp(pw->pw_name, "root") == 0 ){
    exit_pam("fuse not working for root\n");
    return PAM_IGNORE;
  }

  const char * password = NULL;

  int auth_ret = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
  printf("auth_ret=%d\n",auth_ret);

  // ---------------------------------start computing hash------------------------------------

  uint8_t salt[SALTLEN];
  memset( salt, 0x00, SALTLEN );

  uint8_t *pwd = (uint8_t *)strdup(password);
  uint32_t pwdlen = strlen((char *)password);

  uint32_t t_cost = 2;            // 2-pass computation
  uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
  uint32_t parallelism = 1;       // number of threads and lanes
  
  // high-level API
  argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash, HASHLEN);

  for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash[i] ); 
  printf( "\n" );

  // ---------------------------------create directories to save data and to mount the filesystem on------------------------------------

  // create directory to mount fuse on
  char dir_name[PATH_MAX];
  sprintf(dir_name, "/home/%s/private", pw->pw_name);
  printf("trying to create dir %s\n", dir_name);

  int s_dir = mkdir(dir_name, 0770);
  if ( s_dir == -1 && errno != EEXIST ) {
      exit_pam("failed to create mount directory\n");
      return PAM_IGNORE;
  }
  else {
    printf("private files will be visible in %s\n", dir_name);
  }

  // create directory to save data in
  char data_dir_name[PATH_MAX];
  sprintf(data_dir_name, "/home/%s/.private", pw->pw_name);
  printf("trying to create dir %s\n", data_dir_name);

  s_dir = mkdir(data_dir_name, 0770);
  if ( s_dir == -1 && errno != EEXIST ) {
      exit_pam("failed to create data directory\n");
      return PAM_IGNORE;
  }
  else {
    printf("private files will be saved in %s\n", data_dir_name);
  }

  printf("uid %d, gid %d\n", pw->pw_uid, pw->pw_gid);
  chown(dir_name, pw->pw_uid, pw->pw_gid);
  chown(data_dir_name, pw->pw_uid, pw->pw_gid);
  
  // create pipe and write pipe file descriptor to a string variable
  int pipefd[2];
  pipe(pipefd);

  char read_end_pipe_fd[128];
  sprintf(read_end_pipe_fd, "%d", pipefd[0]); // write fd of reading pipe to a string
  
  // start fuse
  int pid = fork();
  if (pid == -1) {
    perror("fork error");
    return PAM_IGNORE;
  } 
  else if (pid == 0) {
    printf("child starting FUSE\n");

    setgid(pw->pw_gid);
    setuid(pw->pw_uid);

    execl("/usr/bin/testfuse", "/usr/bin/testfuse", "-f", dir_name, data_dir_name, read_end_pipe_fd, NULL); //"/home/mountpoint"
    perror("error starting fuse perror \n");
    exit_pam("error starting fuse\n");
    return PAM_IGNORE;
  }
  
  ssize_t n = write(pipefd[1], hash, HASHLEN);
  printf("wrote %lu bytes\n",n);
  if (n < 0 ) {
    perror("error writing key from pipe");
    return PAM_IGNORE;
  }
  
  close(pipefd[0]);
  close(pipefd[1]);

  explicit_bzero(hash, HASHLEN);
  free(pwd);

  // save FUSE PID in file in /run/
  int pid_file = open("/run/testfuse.pid", O_CREAT | O_WRONLY);
  if ( pid_file == -1) {
    perror("opening .pid file\n");
    return PAM_IGNORE;
  }

  printf("authentication ending\n");
  return(PAM_IGNORE);
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  printf("session ending\n");
  
  int pid_file = open("/run/testfuse.pid", O_RDONLY);
  if ( pid_file == -1) {
    perror("opening .pid file\n");
    return PAM_IGNORE;
  }
  
  char buf[BUFLEN];
  if (read(pid_file, buf, BUFLEN) < 0) {
    perror("reading .pid file\n");
    return PAM_IGNORE;
  }

  int fuse_pid = atoi(buf);

  if (kill(fuse_pid, SIGTERM) == -1) {
      perror("sending SIGTERM\n");
      return PAM_IGNORE;
  }

  return(PAM_IGNORE);
}