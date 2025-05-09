#include <stddef.h>

#include <abi-bits/seek-whence.h>
#include <abi-bits/vm-flags.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <abi-bits/stat.h>
#include <mlibc/fsfd_target.hpp>
#include "syscall.h"
#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace [[gnu::visibility("hidden")]] mlibc {

void sys_libc_log(const char *message) {
    __syscall2(1 /* write() */, (size_t)message, strlen(message));
}
[[noreturn]] void sys_libc_panic() {
    sys_libc_log("\nMLIBC PANIC\n");
    __syscall1(60 /* exit() */, 1);
    for (;;);
}

int sys_tcb_set(void *pointer) {
    return -1;
}

[[gnu::weak]] int sys_futex_tid() {
    return -1;
}
int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
    return -1;
}
int sys_futex_wake(int *pointer) {
    return -1;
}

int sys_anon_allocate(size_t size, void **pointer) {
    return -1;
}
int sys_anon_free(void *pointer, size_t size) {
    return -1;
}

int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
    return 0;
}
int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
    return __syscall3(0, fd, (size_t)buf, count);
}
int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
    return -1;
}
int sys_close(int fd) {
    return 0;
}

[[gnu::weak]] int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
    return -1;
}
// mlibc assumes that anonymous memory returned by sys_vm_map() is zeroed by the kernel / whatever is behind the sysdeps
int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
    return -1;
}
int sys_vm_unmap(void *pointer, size_t size) {
    return -1;
}
[[gnu::weak]] int sys_vm_protect(void *pointer, size_t size, int prot) {
    return -1;
}

} //namespace mlibc
