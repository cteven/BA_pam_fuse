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

unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

static char *tvbbl_dir;// Root directory

static int tvbbl_getattr(const char *path, struct stat *stbuf) {
  int res = 0;

  memset(stbuf, 0, sizeof(struct stat));
  char npath[PATH_MAX];
  sprintf(npath, "%s%s", tvbbl_dir, path);

  res = lstat(npath, stbuf);
  if (res == -1) {
    return -errno;
  }
  return 0;
}

static int tvbbl_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
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
  printf("reading %s\n", path);
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

  printf("read %s\n",buf);
  printf("offset %ld\nread %d bytes\nsupposed to read: %lu\n",offset, res, size);
  close(fd);
  return res;
}

static int tvbbl_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  printf("writing %s\n", path);
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

  printf("wrote %d bytes\nsupposed to write: %lu\n", res, size);
  close(fd);
  return res;
}

static int tvbbl_truncate(const char *path, off_t size) {
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);
  int res = truncate(fpath, size);
  if (res == -1)
    return -errno;

  return 0;
}

static int tvbbl_utimens(const char *path, const struct timespec ts[2]) {
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);

  int val = utimensat(0, fpath, ts, AT_SYMLINK_NOFOLLOW);
  if (val == -1)
    return -errno;

  return 0;
}

static int tvbbl_unlink(const char *path) {
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);
  int res = unlink(fpath);
  if (res == -1)
    return -errno;

  return 0;
}

static int tvbbl_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  int fd;
  char fpath[PATH_MAX];
  sprintf(fpath, "%s%s", tvbbl_dir, path);

  fd = creat(fpath, 0777);
  if (fd == -1)
    return -errno;

  close(fd);
  return 0;
}

static int tvbbl_open(const char *path, struct fuse_file_info *fi) {
  if (strcmp(path, "/.validation_file") == 0) {
    return -1;
  }

  char dec_path[PATH_MAX], enc_path[PATH_MAX];
  sprintf(enc_path, "%s%s", tvbbl_dir, path);
  sprintf(dec_path, "%s/dec_%s", tvbbl_dir, ++path);

  if (decrypt_file(enc_path, dec_path, key) != 0) {
    return -1;
  }

  unlink(enc_path);
  rename(dec_path, enc_path);

  return 0;
}

static int tvbbl_release(const char* path, struct fuse_file_info *fi) {
  if (strcmp(path, "/.validation_file") == 0) {
    return -1;
  }

  char dec_path[PATH_MAX], enc_path[PATH_MAX];
  sprintf(dec_path, "%s%s", tvbbl_dir, path);
  sprintf(enc_path, "%s/enc_%s", tvbbl_dir, ++path);

  if (encrypt_file(dec_path, enc_path, key) != 0) {
    return 1;
  }

  unlink(dec_path);
  rename(enc_path, dec_path);

  return 0;
}

static int tvbbl_rename(const char *oldpath, const char *newpath) {
  char oldfpath[PATH_MAX];
  char newfpath[PATH_MAX];
  sprintf(oldfpath, "%s%s", tvbbl_dir, oldpath);
  sprintf(newfpath, "%s%s", tvbbl_dir, newpath);
  int res = rename(oldfpath, newfpath);
  if (res == -1)
    return -errno;

  return 0;
}

static void tvbbl_destroy(void *private_data) {
  printf("unmounting filesystem...\n");
  explicit_bzero(key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
}

int validate_key() {
  char * validation_filename = ".validation_file";
  size_t len_directory_path = strlen(tvbbl_dir);

  char dec_path[PATH_MAX], enc_path[PATH_MAX];
  sprintf(enc_path, "%s/%s", tvbbl_dir, validation_filename);
  sprintf(dec_path, "%s/dec_%s", tvbbl_dir, validation_filename);

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
  if(strcmp(buf, tvbbl_dir) != 0) {
    return -1;
  }
  close(fd);
  unlink(dec_path);

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
  .destroy    = tvbbl_destroy,
};

int main(int argc, char *argv[]) {
  if(argc != 5) {
    fprintf(stderr, "command line arguments\n");
    exit(EXIT_FAILURE);
  }

  char * fuse_arguments[3] = {argv[0], argv[1],argv[2]};
  tvbbl_dir = strdup(argv[3]);
  int pipe_fd = atoi(argv[4]);
  
  uint8_t buffer[crypto_secretstream_xchacha20poly1305_KEYBYTES];

  if(read(pipe_fd, buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES) < 0) {
    perror("error reading key from pipe");
    exit(EXIT_FAILURE);
  }

  memcpy(key, buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  explicit_bzero(buffer, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  
  if (validate_key() == -1 ) {
    fprintf(stderr, "the sent key could not be validated!");
    explicit_bzero(key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
    exit(EXIT_FAILURE);
  }
  printf("validated\n");

  close(pipe_fd);
  return fuse_main(3, fuse_arguments, &tvbbl_oper, NULL);
  
}
