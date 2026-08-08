#define _DARWIN_C_SOURCE 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Read-only filesystem alias used only to reproduce retained R3 components.
 *
 * Cargo and rustc must observe the historical source spelling below because
 * that spelling influenced the retained R3 Wasm bytes.  Every absolute access
 * beneath it is translated to an authenticated source snapshot selected by
 * WASM_BIOTIC_R4_PHYSICAL_ROOT.  Rust path-remapping flags are intentionally
 * not used: those flags themselves alter the retained build identity.
 */

static const char virtual_root[] = "/Users/jacobsullivan/Desktop/wasm-biotic";
static const char physical_variable[] = "WASM_BIOTIC_R4_PHYSICAL_ROOT";

static _Thread_local char translated_paths[8][PATH_MAX];
static _Thread_local unsigned translated_index;

static const char *physical_root(void) {
    const char *value = getenv(physical_variable);
    if (value == NULL || value[0] != '/' || value[1] == '\0') {
        errno = EINVAL;
        return NULL;
    }
    return value;
}

static bool has_prefix(const char *path, const char *prefix) {
    size_t length = strlen(prefix);
    return strncmp(path, prefix, length) == 0 &&
           (path[length] == '\0' || path[length] == '/');
}

static const char *translate_path(const char *path, bool *mapped) {
    *mapped = false;
    if (path == NULL || !has_prefix(path, virtual_root)) {
        return path;
    }
    const char *physical = physical_root();
    if (physical == NULL) {
        return NULL;
    }
    size_t physical_length = strlen(physical);
    size_t virtual_length = sizeof(virtual_root) - 1;
    size_t suffix_length = strlen(path + virtual_length);
    if (physical_length + suffix_length >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    char *output = translated_paths[translated_index++ % 8];
    memcpy(output, physical, physical_length);
    memcpy(output + physical_length, path + virtual_length, suffix_length + 1);
    *mapped = true;
    if (getenv("WASM_BIOTIC_R4_ALIAS_TRACE") != NULL) {
        static const char marker[] = "wasm-biotic-r4-alias: ";
        (void)write(STDERR_FILENO, marker, sizeof(marker) - 1);
        (void)write(STDERR_FILENO, path, strlen(path));
        (void)write(STDERR_FILENO, " -> ", 4);
        (void)write(STDERR_FILENO, output, strlen(output));
        (void)write(STDERR_FILENO, "\n", 1);
    }
    return output;
}

static const char *virtualize_path(const char *path) {
    const char *physical = physical_root();
    if (physical == NULL || path == NULL || !has_prefix(path, physical)) {
        return path;
    }
    size_t physical_length = strlen(physical);
    size_t virtual_length = sizeof(virtual_root) - 1;
    size_t suffix_length = strlen(path + physical_length);
    if (virtual_length + suffix_length >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    char *output = translated_paths[translated_index++ % 8];
    memcpy(output, virtual_root, virtual_length);
    memcpy(output + virtual_length, path + physical_length, suffix_length + 1);
    return output;
}

static bool flags_write(int flags) {
    return (flags & O_ACCMODE) != O_RDONLY ||
           (flags & (O_APPEND | O_CREAT | O_TRUNC)) != 0;
}

static int wb_open(const char *path, int flags, ...) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    if (translated == NULL) return -1;
    if (mapped && flags_write(flags)) {
        errno = EROFS;
        return -1;
    }
    if ((flags & O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        mode_t mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
        return open(translated, flags, mode);
    }
    return open(translated, flags);
}

static int wb_openat(int descriptor, const char *path, int flags, ...) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    if (translated == NULL) return -1;
    if (mapped && flags_write(flags)) {
        errno = EROFS;
        return -1;
    }
    if ((flags & O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        mode_t mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
        return openat(descriptor, translated, flags, mode);
    }
    return openat(descriptor, translated, flags);
}

static int wb_stat(const char *path, struct stat *information) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    return translated == NULL ? -1 : stat(translated, information);
}

static int wb_lstat(const char *path, struct stat *information) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    return translated == NULL ? -1 : lstat(translated, information);
}

static int wb_fstatat(int descriptor, const char *path, struct stat *information, int flags) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    return translated == NULL ? -1 : fstatat(descriptor, translated, information, flags);
}

static int wb_access(const char *path, int mode) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    if (translated == NULL) return -1;
    if (mapped && (mode & W_OK) != 0) {
        errno = EROFS;
        return -1;
    }
    return access(translated, mode);
}

static DIR *wb_opendir(const char *path) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    return translated == NULL ? NULL : opendir(translated);
}

static int wb_chdir(const char *path) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    return translated == NULL ? -1 : chdir(translated);
}

static ssize_t wb_readlink(const char *path, char *buffer, size_t size) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    return translated == NULL ? -1 : readlink(translated, buffer, size);
}

static ssize_t wb_readlinkat(int descriptor, const char *path, char *buffer, size_t size) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    return translated == NULL ? -1 : readlinkat(descriptor, translated, buffer, size);
}

static char *wb_realpath(const char *path, char *resolved) {
    bool mapped;
    const char *translated = translate_path(path, &mapped);
    if (translated == NULL) return NULL;
    char physical_result[PATH_MAX];
    if (realpath(translated, physical_result) == NULL) return NULL;
    const char *visible = virtualize_path(physical_result);
    if (visible == NULL) return NULL;
    if (resolved == NULL) return strdup(visible);
    strcpy(resolved, visible);
    return resolved;
}

static char *wb_getcwd(char *buffer, size_t size) {
    char physical_result[PATH_MAX];
    if (getcwd(physical_result, sizeof(physical_result)) == NULL) return NULL;
    const char *visible = virtualize_path(physical_result);
    if (visible == NULL) return NULL;
    size_t required = strlen(visible) + 1;
    if (buffer == NULL) {
        size_t allocation = size == 0 ? required : size;
        if (allocation < required) {
            errno = ERANGE;
            return NULL;
        }
        buffer = malloc(allocation);
        if (buffer == NULL) return NULL;
    } else if (size < required) {
        errno = ERANGE;
        return NULL;
    }
    memcpy(buffer, visible, required);
    return buffer;
}

#define INTERPOSE(replacement, original)                                      \
    __attribute__((used)) static const struct {                              \
        const void *replacement;                                              \
        const void *original;                                                 \
    } interpose_##original __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&replacement,                                \
        (const void *)(uintptr_t)&original                                    \
    }

INTERPOSE(wb_open, open);
INTERPOSE(wb_openat, openat);
INTERPOSE(wb_stat, stat);
INTERPOSE(wb_lstat, lstat);
INTERPOSE(wb_fstatat, fstatat);
INTERPOSE(wb_access, access);
INTERPOSE(wb_opendir, opendir);
INTERPOSE(wb_chdir, chdir);
INTERPOSE(wb_readlink, readlink);
INTERPOSE(wb_readlinkat, readlinkat);
INTERPOSE(wb_realpath, realpath);
INTERPOSE(wb_getcwd, getcwd);
