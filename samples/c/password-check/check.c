#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s WORD\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "open-sesame") == 0) {
        puts("accepted");
        return 0;
    }
    puts("rejected");
    return 1;
}
