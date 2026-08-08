#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s PROGRAM [ARG ...]\n", argv[0]);
        return 64;
    }
    const char *library = getenv("WASM_BIOTIC_R4_ALIAS_LIBRARY");
    if (library == NULL || library[0] != '/') {
        fprintf(stderr, "WASM_BIOTIC_R4_ALIAS_LIBRARY must be absolute\n");
        return 64;
    }
    if (setenv("DYLD_INSERT_LIBRARIES", library, 1) != 0) {
        fprintf(stderr, "setenv: %s\n", strerror(errno));
        return 70;
    }
    execv(argv[1], &argv[1]);
    fprintf(stderr, "execv %s: %s\n", argv[1], strerror(errno));
    return 126;
}
