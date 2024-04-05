#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

int main() {
    DIR *dir;
    struct dirent *entry;
    struct stat fileStat;

    // Open current directory
    dir = opendir("./test2");
    if (dir == NULL) {
        perror("Error opening directory");
        return 1;
    }

    // Read directory entries
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Get file size
        printf("name: %s\n",entry->d_name);
        char path[1024];
        sprintf(path, "./test2/%s",entry->d_name);
        if (stat(path, &fileStat) == -1) {
            perror("Error getting file information");
            continue;
        }

        // Print filename and size
        printf("File: %s, Size: %ld bytes\n", entry->d_name, fileStat.st_size);
    }

    // Close directory
    closedir(dir);

    return 0;
}
