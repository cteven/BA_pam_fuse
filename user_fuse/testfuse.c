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

#define BUFFER_SIZE 1024

unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

static char *data_dir; // Root directory

static int enc_dir_getattr(const char *path, struct stat *stbuf) {
  int res = 0;

  memset(stbuf, 0, sizeof(struct stat));
  char npath[PATH_MAX];
  sprintf(npath, "%s%s", data_dir, path);

  res = lstat(npath, stbuf);
  if (res == -1) {
    return -errno;
  }
  return 0;
}

static int enc_dir_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", data_dir, path);

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

static int enc_dir_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", data_dir, path);

  int fd = open(fpath, O_RDONLY);
  if (fd == -1)
    return -errno;

  int res = pread(fd, buf, size, offset);
  if (res == -1) {
    res = -errno;
  }
    
  close(fd);

  return res;
}

static int enc_dir_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", data_dir, path);

  int fd = open(fpath, O_WRONLY);
  if (fd == -1) {
    return -errno;
  }

  int res = pwrite(fd, buf, size, offset);
  if (res == -1) {
    res = -errno;
  }

  close(fd);
  return res;
}

static int enc_dir_truncate(const char *path, off_t size) {
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", data_dir, path);
  int res = truncate(fpath, size);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_dir_utimens(const char *path, const struct timespec ts[2]) {
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", data_dir, path);

  int val = utimensat(0, fpath, ts, AT_SYMLINK_NOFOLLOW);
  if (val == -1)
    return -errno;

  return 0;
}

static int enc_dir_unlink(const char *path) {
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", data_dir, path);
  int res = unlink(fpath);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_dir_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  int fd;
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", data_dir, path);

  fd = open(fpath, fi->flags, S_IRWXU);
  if (fd == -1 ) {
    return -errno;
  }

  fi->fh = fd;
  
  return 0;
}

static int enc_dir_open(const char *path, struct fuse_file_info *fi) {
  if (strcmp(path, "/.validation_file") == 0) {
    return -1;
  }

  char dec_path[PATH_MAX], enc_path[PATH_MAX];
  sprintf(enc_path, "%s%s", data_dir, path);
  sprintf(dec_path, "%s%s_dec", data_dir, path);

  if (decrypt_file(enc_path, dec_path, key) != 0) {
    return -1;
  }

  unlink(enc_path);
  rename(dec_path, enc_path);

  return 0;
}

static int enc_dir_release(const char* path, struct fuse_file_info *fi) {
  if (strcmp(path, "/.validation_file") == 0) {
    return -1;
  }

  char dec_path[PATH_MAX], enc_path[PATH_MAX];
  sprintf(dec_path, "%s%s", data_dir, path);
  sprintf(enc_path, "%s%s_enc", data_dir, path);

  if (encrypt_file(dec_path, enc_path, key) != 0) {
    return 1;
  }

  unlink(dec_path);
  rename(enc_path, dec_path);

  return 0;
}

static int enc_dir_rename(const char *oldpath, const char *newpath) {
  char oldfpath[PATH_MAX];
  char newfpath[PATH_MAX];
  sprintf(oldfpath, "%s%s", data_dir, oldpath);
  sprintf(newfpath, "%s%s", data_dir, newpath);
  int res = rename(oldfpath, newfpath);
  if (res == -1)
    return -errno;

  return 0;
}

static void enc_dir_destroy(void *private_data) {
  printf("unmounting filesystem...\n");
  explicit_bzero(key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
}

int validate_key() {
  char * validation_filename = ".validation_file";
  size_t len_directory_path = strlen(data_dir);

  char dec_path[PATH_MAX], enc_path[PATH_MAX];
  sprintf(enc_path, "%s/%s", data_dir, validation_filename);
  sprintf(dec_path, "%s/%s_dec", data_dir, validation_filename);

  if (decrypt_file(enc_path, dec_path, key) != 0) {
    return -1;
  }

  char * buf = malloc(len_directory_path+1);

  int fd = open(dec_path, O_RDONLY);
  if (fd == -1) {
    return -1;
  }

  int w = read(fd, buf, len_directory_path);
  if (w == -1 || w != len_directory_path) {
    return -1;
  }
  buf[len_directory_path] = '\0';
  if(strcmp(buf, data_dir) != 0) {
    return -1;
  }
  close(fd);
  unlink(dec_path);

  return 0;
}

static struct fuse_operations enc_dir_oper = {
  .getattr	= enc_dir_getattr,
  .open		= enc_dir_open,
  .read		= enc_dir_read,
  .write		= enc_dir_write,
  .create		= enc_dir_create,
  .truncate   = enc_dir_truncate,
  .utimens    = enc_dir_utimens,
  .readdir    = enc_dir_readdir,
  .unlink     = enc_dir_unlink,
  .release    = enc_dir_release,
  .rename     = enc_dir_rename,
  .destroy    = enc_dir_destroy,
};

int main(int argc, char *argv[]) {
  if(argc != 4) {
    fprintf(stderr, "command line arguments\n");
    exit(EXIT_FAILURE);
  }

  char * fuse_arguments[2] = {argv[0], argv[1]};
  data_dir = strdup(argv[2]);
  int pipe_fd = atoi(argv[3]);
  
  uint8_t buffer[crypto_secretstream_xchacha20poly1305_KEYBYTES];

  if(read(pipe_fd, buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES) < 0) {
    perror("error reading key from pipe");
    exit(EXIT_FAILURE);
  }
  close(pipe_fd);

  memcpy(key, buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  explicit_bzero(buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  
  if (validate_key() == -1 ) {
    fprintf(stderr, "the sent key could not be validated!");
    explicit_bzero(key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
    exit(EXIT_FAILURE);
  }
  printf("validated\n");

  return fuse_main(2, fuse_arguments, &enc_dir_oper, NULL);
  
}
