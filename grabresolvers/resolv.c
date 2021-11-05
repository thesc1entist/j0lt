#include <stdio.h> 
#include <stdlib.h>
#include <errno.h>
#include <string.h> 

// openssl s_client -connect raw.githubusercontent.com:443
// GET /thesc1entist/j0lt/main/j0lt-resolv.txt HTTP/1.1
// Host: raw.githubusercontent.com

#define MAXREAD_J0LT 0x30
#define NCOMMANDS_J0LT 3
#define COMMAND_PATH_J0LT 0
#define COMMAND_RM_J0LT 1
#define COMMAND_WGET_J0LT 2

const char* g_commands[ NCOMMANDS_J0LT ] = {
    "/tmp/resolv.txt",
    "rm /tmp/resolv.txt",
    "wget -O /tmp/resolv.txt https://raw.githubusercontent.com/thesc1entist/j0lt/main/j0lt-resolv.txt"
};

int main(int argc, char** argv)
{
    FILE* fptr;
    char lineptr[ MAXREAD_J0LT ];
    size_t nread;
    system(g_commands[ COMMAND_WGET_J0LT ]); // grab resolv list
    fptr = fopen(g_commands[ COMMAND_PATH_J0LT ], "r");

    if (fptr == NULL) {
        perror("unable to read file");
        exit(EXIT_FAILURE);
    }

    while (fgets(lineptr, MAXREAD_J0LT, fptr) != NULL) {
        if (lineptr[ 0 ] == '#')
            continue;
        nread = strlen(lineptr);
        lineptr[ nread - 1 ] = '\0';
        puts(lineptr);
    }

    system(g_commands[ COMMAND_RM_J0LT ]); // remove resolv list
    fclose(fptr);

    return 0;
}