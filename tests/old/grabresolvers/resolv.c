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

void Red(void) {
    printf("\033[1;31m");
}

void Green(void) {
    printf("\033[0;32m");
}

void Reset(void) {
    printf("\033[0m");
}

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

    Green( );
    printf("+ resolv list saved to %s\n", g_commands[ COMMAND_PATH_J0LT ]);
    Reset( );

    while (fgets(lineptr, MAXREAD_J0LT, fptr) != NULL) {
        if (lineptr[ 0 ] == '#')
            continue;
        nread = strlen(lineptr);
        lineptr[ nread - 1 ] = '\0';
        // puts(lineptr);
    }

    Red( );
    printf("+ removing resolv list from %s\n", g_commands[ COMMAND_PATH_J0LT ]);
    Reset( );
    system(g_commands[ COMMAND_RM_J0LT ]); // remove resolv list
    fclose(fptr);

    return 0;
}