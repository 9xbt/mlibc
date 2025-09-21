#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <termios.h>

#include <abi-bits/seek-whence.h>
#include <abi-bits/vm-flags.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <abi-bits/stat.h>
#include <mlibc/fsfd_target.hpp>

#include <syscall.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace [[gnu::visibility("hidden")]] mlibc {

    void sys_libc_log(const char *message) {
        __syscall3(SYS_write, 2, (long)message, strlen(message));
        __syscall3(SYS_write, 2, (long)"\n", 1);
    }

    [[noreturn]] void sys_libc_panic() {
        __syscall3(SYS_write, 2, (long)"\n", 1);
        __syscall1(SYS_exit, 1);
        __builtin_unreachable();
    }

    int sys_tcb_set(void *pointer) {
        return __syscall1(SYS_set_tls, (long)pointer);
    }

    [[gnu::weak]] int sys_futex_tid() {
        return 0;
    }

    int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
        return -ENOSYS;
    }

    int sys_futex_wake(int *pointer) {
        return -ENOSYS;
    }

    int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
        auto ret = __syscall6(SYS_mmap, (long)hint, (long)size, (long)prot, (long)flags, (long)fd, (long)offset);
        if (ret < 0)
            return -ret;
        *window = (void *)ret;
        return 0;
    }

    int sys_vm_unmap(void *pointer, size_t size) {
        return __syscall2(SYS_munmap, (long)pointer, size);
    }

    int sys_anon_allocate(size_t size, void **pointer) {
        return sys_vm_map(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, pointer);
    }

    int sys_anon_free(void *pointer, size_t size) {
        return sys_vm_unmap(pointer, size);
    }

    int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
        auto ret = __syscall3(SYS_open, (long)pathname, flags, mode);
        if (ret < 0)
            return -ret;
        *fd = ret;
        return 0;
    }

    int sys_read(int fd, void *buf, size_t len, ssize_t *read) {
        auto ret = __syscall3(SYS_read, fd, (long)buf, len);
        if (ret < 0)
            return -ret;
        *read = ret;
        return 0;
    }

    int sys_write(int fd, const void *buf, size_t len, ssize_t *written) {
        auto ret = __syscall3(SYS_write, fd, (long)buf, len);
        if (ret < 0)
            return -ret;
        *written = ret;
        return 0;
    }

    int sys_seek(int fd, off_t offset, int whence, off_t *seek) {
        auto ret = __syscall3(SYS_seek, fd, offset, whence);
        if (ret < 0)
            return -ret;
        *seek = ret;
        return 0;
    }

    int sys_close(int fd) {
        return __syscall1(SYS_close, fd);
    }

    int sys_exit(int status) {
        return __syscall1(SYS_exit, status);
    }

    int sys_clock_get(int clock, time_t *secs, long *nanos) {
        return 0;
    }

    int sys_isatty(int fd) {
        char _[8];
        auto ret = __syscall3(SYS_ioctl, fd, TIOCGWINSZ, (long)_);
        if (ret < 0)
            return 1;
        return 0;
    }

} //namespace mlibc

extern "C" { 
    void *__dso_handle __attribute__((visibility("hidden"))) = nullptr;
}
