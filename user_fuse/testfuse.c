#define FUSE_USE_VERSION 39

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include "../utils/enc_utils.h"
#include <sodium.h>

// damit vscode nicht mehr meckert
// #include <linux/limits.h>
// #include <linux/fcntl.h>

#define BUFFER_SIZE 1024
#define FIFO_NAME "/tmp/pam_fifo1"

unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

static char *tvbbl_dir// Root directory

void sigterm_handler(int signum) {
    printf("Received SIGTERM signal. Exiting...\n");
    explicit_bzero(key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
    exit(EXIT_SUCCESS);
}

static int tvbbl_getattr(const char *path, struct stat *stbuf) {
  printf("getattr path: %s\n", path);

  int res = 0;

  memset(stbuf, 0, sizeof(struct stat));
  char npath[PATH_MAX];
  sprintf(npath, "%s%s", tvbbl_dir, path);
  printf("path %s\n",npath);


  // res = lstat(npath, stbuf);
  // printf("res: %d\n",res);
  // printf("uid, gid: %d, %d\n", stbuf->st_uid, stbuf->st_gid);
  // if (res == -1) {
  //   return -errno;
  // }

  // memset(stbuf, 0, sizeof(struct stat));
  // if (strcmp(path, "/") == 0) {
  //       // Retrieve attributes of the mountpoint directory
  //       res = lstat(tvbbl_dir, stbuf);
  //       if (res == -1)
  //           return -errno;
  //   }
  // else {
  //   res = lstat(npath, stbuf);
  //   stbuf->st_mode = stbuf->st_mode | 0777;
  //   if (res == -1)
  //     return -errno;
  // }

  // memset(stbuf, 0, sizeof(struct stat));
  // if ((strcmp(path, "/") == 0) ) {
  //   // stbuf->st_mode = S_IFDIR | 0700;    // ausschließlich dem owner des Ordners den Zugang erlauben
  //   // stbuf->st_nlink = 2;

  //   res = lstat(npath, stbuf); // Get attributes of the root directory
  //   printf("res: %d\npwname %u\n", res, stbuf->st_uid);
  //   if (res == -1)
  //       return -errno;
  // } 
  // else {
  //   res = lstat(npath, stbuf);
  //   stbuf->st_mode = stbuf->st_mode | 0777;
  //   if (res == -1)
  //     return -errno;
  // }

  // struct passwd *pwd;
  // struct group *grp;
  // struct stat file_stat;

  // // Check if the requested path exists
  // if (strcmp(path, "/") == 0) {
  //     // Root directory
  //     res = lstat(npath, stbuf); // Get attributes of the root directory
  //     printf("res: %d\npwname %u\n", res, stbuf->st_uid);
  //     if (res == -1)
  //         return -errno;
  // } else {
  //     // Other file or directory
  //     res = lstat(npath, &file_stat); // Get attributes of the specified file or directory
  //     if (res == -1)
  //         return -errno;

  //     // Copy the attributes to stbuf
  //     memcpy(stbuf, &file_stat, sizeof(struct stat));
  // }

  // // Get owner information
  // pwd = getpwuid(stbuf->st_uid);
  // if (pwd == NULL)
  //     return -errno;
  // printf("pwd %s\n", pwd->pw_name);

  // // Get group information
  // grp = getgrgid(stbuf->st_gid);
  // if (grp == NULL)
  //     return -errno;

  // // Update file mode if it is a directory
  // if (S_ISDIR(stbuf->st_mode))
  //     stbuf->st_mode |= S_IXUSR | S_IXGRP | S_IXOTH;

  // // Update stbuf with owner and group information
  // stbuf->st_uid = pwd->pw_uid; // Owner user ID
  // stbuf->st_gid = grp->gr_gid; // Group ID

  //   return 0;

  // return res;
}

static int tvbbl_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  printf("reading directory %s\n",path);

  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);

  DIR *dp = opendir(fpath);
  if (dp == NULL)
    return -errno;

  struct dirent *de;
  while ((de = readdir(dp)) != NULL) {
    if (filler(buf, de->d_name, NULL, 0))
      break;
  }

  closedir(dp);
  return 0;
}

static int tvbbl_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  printf("reading file %s\n",path);
  int fd;
  int res;

  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);
  fd = open(fpath, O_RDONLY);
  if (fd == -1)
    return -errno;

  res = pread(fd, buf, size, offset);
  if (res == -1)
    res = -errno;

  close(fd);
  return res;
}

static int tvbbl_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  printf("writing file %s\n",path);
  int fd;
  int res;

  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);
  fd = open(fpath, O_WRONLY);
  if (fd == -1)
    return -errno;

  res = pwrite(fd, buf, size, offset);
  if (res == -1)
    res = -errno;

  close(fd);
  return res;
}

static int tvbbl_truncate(const char *path, off_t size) {
  printf("truncate %s\n",path);
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);
  int res = truncate(fpath, size);
  if (res == -1)
    return -errno;

  return 0;
}

static int tvbbl_utimens(const char *path, const struct timespec ts[2]) {
  printf("utimes %s\n",path);

  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);

  int val = utimensat(0, fpath, ts, AT_SYMLINK_NOFOLLOW);
  if (val == -1)
    return -errno;

  return 0;
}

static int tvbbl_unlink(const char *path) {
  printf("remove %s\n",path);
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);
  int res = unlink(fpath);
  if (res == -1)
    return -errno;

  return 0;
}

static int tvbbl_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  printf("creating %s\n",path);
  int fd;
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);
  fd = creat(fpath, 0777);
  if (fd == -1)
    return -errno;

  close(fd);

  // char dec_path[PATH_MAX], enc_path[PATH_MAX];
  
  // sprintf(dec_path, "%s/origin_%s", tvbbl_dir, path++);
  // printf("new origin path %s\n", dec_path);

  // sprintf(enc_path, "%s/enc_%s", tvbbl_dir, path++);
  // printf("enc path %s\n", enc_path);

  // if (encrypt_file(enc_path, dec_path, key) != 0) {
  //   return 1;
  // }

  return 0;
}

static int tvbbl_open(const char *path, struct fuse_file_info *fi) {
  printf("opening and decrypting file %s\n", path);
  char dec_path[PATH_MAX], enc_path[PATH_MAX];

  sprintf(enc_path, "%s%s", tvbbl_dir, path);
  printf("o new dec path %s\n", dec_path);

  sprintf(dec_path, "%s/dec_%s", tvbbl_dir, ++path);
  printf("o enc path %s\n", enc_path);

  if (decrypt_file(enc_path, dec_path, key) != 0) {
    printf("\nrip\n\n");
    return 1;
  }

  unlink(enc_path);
  rename(dec_path, enc_path);

  return 0;
}

static int tvbbl_release(const char* path, struct fuse_file_info *fi) {
  printf("releasing and encrypting file %s\n", path);
  char dec_path[PATH_MAX], enc_path[PATH_MAX];
  
  sprintf(dec_path, "%s%s", tvbbl_dir, path);
  printf("r new dec path %s\n", dec_path);

  sprintf(enc_path, "%s/enc_%s", tvbbl_dir, ++path);
  printf("r enc path %s\n", enc_path);

  if (encrypt_file(dec_path, enc_path, key) != 0) {
    return 1;
  }

  unlink(dec_path);
  rename(enc_path, dec_path);

  return 0;
}

static int tvbbl_rename(const char *oldpath, const char *newpath)
{
    char oldfpath[PATH_MAX];
    char newfpath[PATH_MAX];
    sprintf(oldfpath, "%s%s", tvbbl_dir, oldpath);
    sprintf(newfpath, "%s%s", tvbbl_dir, newpath);
    int res = rename(oldfpath, newfpath);
    if (res == -1)
        return -errno;

    return 0;
}

static struct fuse_operations tvbbl_oper = {
  .getattr	= tvbbl_getattr,
  .open		= tvbbl_open,
  .read		= tvbbl_read,
  .write		= tvbbl_write,
  .create		= tvbbl_create,
  .truncate   = tvbbl_truncate,
  .utimens    = tvbbl_utimens,
  .readdir    = tvbbl_readdir,
  .unlink     = tvbbl_unlink,
  .release    = tvbbl_release,
  .rename     = tvbbl_rename,
};

int main(int argc, char *argv[]) {

  printf("init\n");
  int res = lstat(tvbbl_dir, &tvbbl_dir_stat);
  printf("lstat %d\n", res);
  
  if ( res == -1) {
    perror("lstat info about mountpoint");
  } 
  puts("init ending");

  // if (signal(SIGTERM, sigterm_handler) == SIG_ERR) {
  //   perror("signal");
  //   exit(EXIT_FAILURE);
  // }
  // puts("testfuse");

  // char * fuse_arguments[3] = {argv[0], argv[2],argv[3]};
  // int pipe_fd = atoi(argv[1]);
  // printf("fd_string int: %d\n",pipe_fd);

  // uint8_t buffer[crypto_secretstream_xchacha20poly1305_KEYBYTES];

  // if(read(pipe_fd, buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES) < 0) {
  //   perror("error reading key from pipe");
  //   exit(EXIT_FAILURE);
  // }

  // printf("received message(hex):\n");
  // for( int i=0; i<32; ++i ) printf( "%x ", buffer[i] ); 
  //   printf( "\n" );

  tvbbl_dir = strdup(argv[2]);
  printf("new data_dir %s\n",tvbbl_dir);


  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  if (sodium_init() != 0) {
    return 1;
  }
  crypto_secretstream_xchacha20poly1305_keygen(key);
  puts("key generated");
  // implement PIPE here

  // mkfifo(FIFO_NAME, 0660);

  
  // int fifo_fd = fdopen(pipe_fd, "r");
  // if (fifo_fd < 0) {
  //   perror("error opening pipe");
  //   exit(EXIT_FAILURE);
  // }

  // ssize_t n;
  // do {
  //   n = read(fifo_fd, buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  //   printf("read %lu bytes\n",n);
  //   if (n < 0 ) {
  //     perror("error reading key from pipe");
  //     exit(EXIT_FAILURE);
  //   }
  // } while (n);
  
  
  // while(n) {
  //   puts("test");
  //   n = read(fifo_fd, buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  //   printf("read %lu bytes\n",n);
  //   if (n < 0 ) {
  //     perror("error reading key from pipe");
  //     exit(EXIT_FAILURE);
  //   }
  // }

  


  // memcpy(key, buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  // explicit_bzero(buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  

  // close(pipe_fd);
  // close(fifo_fd);
  puts("starting fuse");
  return fuse_main(argc, argv, &tvbbl_oper, NULL);
  
}
