#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <writefile> <writestr>\n", argv[0]);
        exit(1);
    }

    const char *writefile = argv[1];
    const char *writestr = argv[2];

    // syslog open (ident = program name, option = log to stderr too, facility = LOG_USER)
    openlog(argv[0], LOG_PID | LOG_PERROR, LOG_USER);

    // Check if directory exists
    char path_copy[1024];
    strncpy(path_copy, writefile, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    char *dir = dirname(path_copy);

    if (access(dir, F_OK) != 0) {
        syslog(LOG_ERR, "Directory %s does not exist: %s", dir, strerror(errno));
        closelog();
        exit(1);
    }

    // Write to file
    FILE *fp = fopen(writefile, "w");
    if (fp == NULL) {
        syslog(LOG_ERR, "Failed to open file %s: %s", writefile, strerror(errno));
        closelog();
        exit(1);
    }

    if (fputs(writestr, fp) == EOF) {
        syslog(LOG_ERR, "Failed to write to file %s: %s", writefile, strerror(errno));
        fclose(fp);
        closelog();
        exit(1);
    }

    fclose(fp);

    // Log success with LOG_DEBUG
    syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);

    closelog();
    return EXIT_SUCCESS;
}

