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

static char *tvbbl_dir; // Root directory

static int tvbbl_getattr(const char *path, struct stat *stbuf) {
  printf("getattr path: %s\n", path);

  int res = 0;

  memset(stbuf, 0, sizeof(struct stat));
  char npath[PATH_MAX];
  sprintf(npath, "%s%s", tvbbl_dir, path);
  printf("path %s\n",tvbbl_dir);


  if ((strcmp(path, "/") == 0) ) {
    stbuf->st_mode = S_IFDIR | 0700;    // ausschließlich dem owner des Ordners den Zugang erlauben
    stbuf->st_nlink = 2;
  } 
  else {
    res = lstat(npath, stbuf);
    stbuf->st_mode = stbuf->st_mode | 0777;
    if (res == -1)
      return -errno;
  }

  return 0;

 
  // puts("haja1");
  // if (strcmp(path, "/") == 0) {
  //   puts("haja2");
  //   stbuf->st_mode = S_IFDIR | 0777;
  //   stbuf->st_nlink = 2;
  //   puts("haja21");
  //   memcpy(stbuf, &tvbbl_dir_stat, sizeof(struct stat));
  //   puts("haja3");
  // } 
  // else {
  //   puts("haja4");
  //   res = lstat(npath, stbuf);
  //   if (res == -1) {
  //     return -errno;
  //   }
  //   puts("haja5");
  //   stbuf->st_mode = stbuf->st_mode | 0777;
  //   puts("haja6");
  //   if (res == -1)
  //     return -errno;
  // }
  // puts("haja7");
  // return 0;
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


static struct fuse_operations tvbbl_oper = {
  .getattr	= tvbbl_getattr,
  .readdir  = tvbbl_readdir,
};

int main(int argc, char *argv[]) {

  puts("starting fuse");
  return fuse_main(argc, argv, &tvbbl_oper, NULL);
  
}
