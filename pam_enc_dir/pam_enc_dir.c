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
#include <pwd.h>
#include <limits.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "../utils/enc_utils.h"
#include "argon2.h"

#define FUSE_SUPER_MAGIC 0x65735546

#define MOUNT_DIRECTORY "/home/%s/private"
#define DATA_DIRECTORY "/home/%s/.private"
#define HASHLEN crypto_secretstream_xchacha20poly1305_KEYBYTES
#define SALTLEN 16
#define BUFLEN 32

static uint8_t hash[HASHLEN];

struct passwd *pw;

// can be called to overwrite the hash before the PAM Module is ending
void exit_pam(char * msg) {
  fprintf(stderr, "error: %s", msg);
  explicit_bzero(hash, HASHLEN);
}

struct passwd * get_user_info(pam_handle_t *pamh) {
  struct passwd * pw;
  const char *user;
  if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS)
  {
    exit_pam("failed to get username\n");
    return NULL;
  }
  if ((pw = getpwnam(user)) == NULL)
  {
    exit_pam("couldn't find username\n");
    return NULL;
  }
  if (strcmp(pw->pw_name, "root") == 0 ){
    exit_pam("fuse not working for root\n");
    return NULL;
  }
  return pw;
}

int is_fuse_running(char * directory) {
  struct statfs fuse_info;

  if (statfs(directory, &fuse_info) !=0 ) {
    return -1;
  }
  if (fuse_info.f_type == FUSE_SUPER_MAGIC) { // fuse is running
    return 1;
  }
  return 0;
}

int compute_hash(const char * password) {
  uint8_t salt[SALTLEN];
  memset( salt, 0x74, SALTLEN );

  uint8_t *pwd = (uint8_t *)strdup(password);
  if(pwd == NULL) {
    perror("strdup");
    return -1;
  }
  uint32_t pwdlen = strlen((char *)password);

  uint32_t t_cost = 1;            // 2-pass computation
  uint32_t m_cost = (1<<21);      // 64 mebibytes memory usage
  uint32_t parallelism = 4;       // number of threads and lanes
  
  // high-level API
  int ret = argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash, HASHLEN);
  if (ret != ARGON2_OK) {
    return -1;
  }

  free(pwd);

  return 0;
}

int create_and_encrypt_validation_file(char directory[PATH_MAX], char * content) {
  size_t len_content = strlen(content);

  char filename_dec[PATH_MAX];
  sprintf(filename_dec, "%s/.validation_file_dec", directory);
  char filename_enc[PATH_MAX];
  sprintf(filename_enc, "%s/.validation_file", directory);



  int ret = access(directory, F_OK);
  if (ret == 0) { // directory exists
    if(access(directory, R_OK) == -1)
      return 0; // PAM Module doesnt have read permissions, so the directory and validation file was already created in the past
  }
  
  ret = access(filename_enc, F_OK);
  if (ret == 0) {
    return 0;
  }

  int fd = open(filename_dec, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    return -1;
  }

  int w = write(fd, content, len_content);
  if (w == -1 || w != len_content) {
    return -1;
  }

  close(fd);

  encrypt_file(filename_dec, filename_enc, hash);
  unlink(filename_dec);

  chown(filename_enc, pw->pw_uid, pw->pw_gid);

  int fd2 = open(filename_enc, O_RDONLY);
  if (fd == -1) {
    return -1;
  }

  int immutable_flag = FS_IMMUTABLE_FL;
  int m = ioctl(fd2,FS_IOC_SETFLAGS, &immutable_flag);
  if (m == -1) {
    perror("ioctl");
    return -1;
  }

  close(fd2);

  return 0;
}

/* PAM entry point for authentication verification */
// gets called in a situation where the user has to put in their PW
// also runs this function, when user PW is wrong
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  pw = get_user_info(pamh);
  if (pw == NULL) {
    return PAM_IGNORE;
  }
  
  // create directory to mount fuse on
  char mount_dir_name[PATH_MAX];
  sprintf(mount_dir_name, MOUNT_DIRECTORY, pw->pw_name);

  if ( is_fuse_running(mount_dir_name) == 1) {
    printf("fuse is running already\n");
    return PAM_IGNORE;
  }

  const char * password = NULL;
  pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

  // compute hash from user password
  compute_hash(password);

  // create directories to save data and to mount the filesystem on
  int s_dir = mkdir(mount_dir_name, 0770);
  if ( s_dir == -1 && errno != EEXIST ) {
      exit_pam("failed to create mount directory\n");
      return PAM_IGNORE;
  }

  // create directory to save data in
  char data_dir_name[PATH_MAX];
  sprintf(data_dir_name, DATA_DIRECTORY, pw->pw_name);

  s_dir = mkdir(data_dir_name, 0770);
  if ( s_dir == -1 && errno != EEXIST ) {
      exit_pam("failed to create data directory\n");
      return PAM_IGNORE;
  }

  // create and encrypt the validation file in the .private directory
  if (create_and_encrypt_validation_file(data_dir_name, data_dir_name) != 0 ) {
    perror("");
    exit_pam("creating and encrypting validation file");
    return PAM_IGNORE;
  }

  // change directories owner and group
  chown(mount_dir_name, pw->pw_uid, pw->pw_gid);
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
    setgid(pw->pw_gid);
    setuid(pw->pw_uid);

    execl("/usr/bin/enc_dir_fuse", "/usr/bin/enc_dir_fuse",  mount_dir_name, data_dir_name, read_end_pipe_fd, NULL); //"/home/mountpoint"
    perror("error starting fuse perror \n");
    exit_pam("error starting fuse\n");
    return PAM_IGNORE;
  }
  
  ssize_t n = write(pipefd[1], hash, HASHLEN);
  if (n < 0 ) {
    perror("error writing key from pipe");
    return PAM_IGNORE;
  }
  
  close(pipefd[0]);
  close(pipefd[1]);

  explicit_bzero(hash, HASHLEN);
  
  return(PAM_IGNORE);
}

/* PAM entry point for session cleanup */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  pw = get_user_info(pamh);
  if (pw == NULL) {
    return PAM_IGNORE;
  }

  char mount_dir[PATH_MAX];
  sprintf(mount_dir, MOUNT_DIRECTORY, pw->pw_name);
  
  if (is_fuse_running(mount_dir) != 1) {
    return PAM_IGNORE;
  }

  if (umount(mount_dir) < 0) {
    perror("umount");
    exit_pam("unmounting failed");
    return PAM_IGNORE;
  }

  return(PAM_IGNORE);
}