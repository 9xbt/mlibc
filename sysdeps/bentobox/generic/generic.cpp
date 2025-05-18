#include <stddef.h>
#include <errno.h>

#include <abi-bits/seek-whence.h>
#include <abi-bits/vm-flags.h>
#include <abi-bits/termios.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <abi-bits/stat.h>
#include <mlibc/fsfd_target.hpp>
#include <abi-bits/signal.h>
#include "syscall.h"
#include <string.h>
#include <stdio.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static inline void *sc_ptr_result(long ret) {
    return (void *)ret;
}

static inline int sc_error(long ret) {
    if (ret < 0 && ret > -4096)
        return -ret;
    return 0;
}

namespace [[gnu::visibility("hidden")]] mlibc {

    /* Fuck github desktop man */

    [[noreturn]] void sys_exit(int status) {
        __syscall1(60 /* exit() */, status);
        __builtin_unreachable();
    }

    void sys_libc_log(const char *message) {
        if (!message) return;
        size_t len = strlen(message);
        if (len > 0)
            __syscall3(1 /* write() */, 2 /* stderr */, (long)message, len);
        __syscall3(1 /* write() */, 2 /* stderr */, (long)"\n", 1);
    }
    
    [[noreturn]] void sys_libc_panic() {
        sys_libc_log("\nMLIBC PANIC\n");
        __syscall1(60 /* exit() */, 1);
        __builtin_unreachable();
    }

    int sys_write(int fd, const void *buff, size_t count, ssize_t *bytes_written) {
        auto ret = __syscall3(1 /* write() */, fd, (long)buff, count);
        if (int e = sc_error(ret); e)
            return e;
        *bytes_written = ret;
        return 0;
    }

    int sys_tcb_set(void *pointer) {
        auto ret = __syscall2(158 /* arch_prctl */, 0x1002 /* ARCH_SET_FS */, (size_t)pointer);
        return sc_error(ret);
    }

    [[gnu::weak]] int sys_futex_tid() {
        return __syscall0(186 /* gettid */);
    }

    int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
        auto ret = __syscall6(202 /* futex */, (long)pointer, 0 /* FUTEX_WAIT */, 
                         expected, (long)time, 0, 0);
        return sc_error(ret);
    }
    
    int sys_futex_wake(int *pointer) {
        auto ret = __syscall6(202 /* futex */, (long)pointer, 1 /* FUTEX_WAKE */, 
                         0x7fffffff, 0, 0, 0);
        return sc_error(ret);
    }

    int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
        auto ret = __syscall3(2 /* open */, (long)pathname, flags, mode);
        if (int e = sc_error(ret); e)
            return e;
        *fd = ret;
        return 0;
    }
    
    int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
        if (fd == 0) {
            fflush(stdout);    
        }

        auto ret = __syscall3(0 /* read */, fd, (size_t)buf, count);
        if (int e = sc_error(ret); e)
            return e;
        *bytes_read = ret;
        return 0;
    }

    int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
        auto ret = __syscall3(8 /* lseek */, fd, offset, whence);
        if (int e = sc_error(ret); e)
            return e;
        *new_offset = ret;
        return 0;
    }

    int sys_close(int fd) {
        auto ret = __syscall1(3 /* close */, fd);
        return sc_error(ret);
    }

    [[gnu::weak]] int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
        long ret;
        
        switch (fsfdt) {
        case fsfd_target::fd:
            ret = __syscall2(5 /* fstat */, fd, (long)statbuf);
            break;
        case fsfd_target::path:
            ret = __syscall2(4 /* stat */, (long)path, (long)statbuf);
            break;
        case fsfd_target::fd_path:
            ret = __syscall4(262 /* newfstatat */, fd, (long)path, (long)statbuf, flags);
            break;
        default:
            return EINVAL;
        }
        
        return sc_error(ret);
    }

    int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
        auto ret = __syscall6(9 /* mmap */, 
                      (long)hint, 
                      (long)size, 
                      (long)prot, 
                      (long)flags, 
                      (long)fd, 
                      (long)offset);
        
        if (int e = sc_error(ret); e)
            return e;
        
        *window = sc_ptr_result(ret);
        return 0;
    }

    int sys_vm_unmap(void *pointer, size_t size) {
        auto ret = __syscall2(11 /* munmap */, (long)pointer, size);
        return sc_error(ret);
    }

    [[gnu::weak]] int sys_vm_protect(void *pointer, size_t size, int prot) {
        auto ret = __syscall3(10 /* mprotect */, (long)pointer, size, prot);
        return sc_error(ret);
    }

    int sys_anon_allocate(size_t size, void **pointer) {
        return sys_vm_map(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0, pointer);
    }
    
    int sys_anon_free(void *pointer, size_t size) {
        return sys_vm_unmap(pointer, size);
    }

    int sys_isatty(int fd) {
        struct termios t;
        auto ret = __syscall3(16 /* ioctl */, fd, 0x5401 /* TCGETS */, (long)&t);
        if (sc_error(ret) == ENOTTY)
            return ENOTTY;
        else if (sc_error(ret))
            return sc_error(ret);
        return 0;
    }

    int sys_ioctl(int fd, unsigned long request, void *arg) {
        auto ret = __syscall3(16 /* ioctl */, fd, request, (long)arg);
        return sc_error(ret);
    }
    
    int sys_clock_get(int clock, time_t *secs, long *nanos) {
        struct timespec tp = {};
        auto ret = __syscall2(228 /* sys_clock_gettime */, clock, (long)&tp);
        if (int e = sc_error(ret); e)
            return e;
        *secs = tp.tv_sec;
        *nanos = tp.tv_nsec;
        return 0;
    }

    int sys_execve(const char *path, char *const argv[], char *const envp[]) {
        auto ret = __syscall3(59 /* sys_execve */, (long)path, (long)argv, (long)envp);
        if (int e = sc_error(ret); e)
            return e;
        return 0;
    }

    int sys_fork(pid_t *child) {
        auto ret = __syscall2(56 /* sys_clone */, SIGCHLD, 0);
        if (int e = sc_error(ret); e)
            return e;
        *child = (pid_t)ret;
        return 0;
    }

} //namespace mlibc

extern "C" { 
    void *__dso_handle __attribute__((visibility("hidden"))) = nullptr;
}