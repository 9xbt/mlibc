#include <stddef.h>
#include <errno.h>

#include <abi-bits/seek-whence.h>
#include <abi-bits/vm-flags.h>
#include <abi-bits/termios.h>
#include <abi-bits/resource.h>
#include <abi-bits/fcntl.h>
#include <abi-bits/utsname.h>
#include <abi-bits/termios.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <abi-bits/stat.h>
#include <mlibc/fsfd_target.hpp>
#include <abi-bits/signal.h>
#include <bentobox/syscalls.h>
#include "syscall.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

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

    [[noreturn]] void sys_exit(int status) {
        __syscall1(SYS_exit, status);
        __builtin_unreachable();
    }

    void sys_libc_log(const char *message) {
        if (!message) return;
        size_t len = strlen(message);
        if (len > 0)
            __syscall3(SYS_write, 2 /* stderr */, (long)message, len);
        __syscall3(SYS_write, 2 /* stderr */, (long)"\n", 1);
    }
    
    [[noreturn]] void sys_libc_panic() {
        __syscall3(SYS_write, 2 /* stderr */, (long)"\n", 1);
        __syscall1(SYS_exit, 1);
        __builtin_unreachable();
    }

    int sys_write(int fd, const void *buff, size_t count, ssize_t *bytes_written) {
        auto ret = __syscall3(SYS_write, fd, (long)buff, count);
        if (int e = sc_error(ret); e)
            return e;
        *bytes_written = ret;
        return 0;
    }

    int sys_tcb_set(void *pointer) {
        auto ret = __syscall2(SYS_arch_prctl, 0x1002 /* ARCH_SET_FS */, (size_t)pointer);
        return sc_error(ret);
    }

    [[gnu::weak]] int sys_futex_tid() {
        return __syscall0(SYS_gettid);
    }

    int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
        auto ret = __syscall6(SYS_futex, (long)pointer, 0 /* FUTEX_WAIT */, 
                         expected, (long)time, 0, 0);
        return sc_error(ret);
    }
    
    int sys_futex_wake(int *pointer) {
        auto ret = __syscall6(SYS_futex, (long)pointer, 1 /* FUTEX_WAKE */, 
                         0x7fffffff, 0, 0, 0);
        return sc_error(ret);
    }

    int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
        auto ret = __syscall3(SYS_open, (long)pathname, flags, mode);
        if (int e = sc_error(ret); e)
            return e;
        *fd = ret;
        return 0;
    }
    
    int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
        if (fd == 0) {
            fflush(stdout);
        }

        auto ret = __syscall3(SYS_read, fd, (size_t)buf, count);
        if (int e = sc_error(ret); e)
            return e;
        *bytes_read = ret;
        return 0;
    }

    int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
        auto ret = __syscall3(SYS_lseek, fd, offset, whence);
        if (int e = sc_error(ret); e)
            return e;
        *new_offset = ret;
        return 0;
    }

    int sys_close(int fd) {
        auto ret = __syscall1(SYS_close, fd);
        return sc_error(ret);
    }

    int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
        long ret;
        
        switch (fsfdt) {
        case fsfd_target::fd:
            ret = __syscall2(SYS_fstat, fd, (long)statbuf);
            break;
        case fsfd_target::path:
            ret = __syscall2(SYS_stat, (long)path, (long)statbuf);
            break;
        case fsfd_target::fd_path:
            ret = __syscall4(SYS_newfstatat, fd, (long)path, (long)statbuf, flags);
            break;
        default:
            return EINVAL;
        }
        
        return sc_error(ret);
    }

    int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
        auto ret = __syscall6(SYS_mmap, 
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
        auto ret = __syscall2(SYS_munmap, (long)pointer, size);
        return sc_error(ret);
    }

    [[gnu::weak]] int sys_vm_protect(void *pointer, size_t size, int prot) {
        auto ret = __syscall3(10 /* SYS_mprotect */, (long)pointer, size, prot);
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
        auto ret = __syscall3(SYS_ioctl, fd, 0x5401 /* TCGETS */, (long)&t);
        if (sc_error(ret) == ENOTTY)
            return ENOTTY;
        else if (sc_error(ret))
            return sc_error(ret);
        return 0;
    }

    int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
        auto ret = __syscall3(SYS_ioctl, fd, request, (long)arg);
        if (int e = sc_error(ret); e)
            return e;
        if (result)
            *result = ret;
        return 0;
    }
    
    int sys_clock_get(int clock, time_t *secs, long *nanos) {
        struct timespec tp = {};
        auto ret = __syscall2(SYS_clock_gettime, clock, (long)&tp);
        if (int e = sc_error(ret); e)
            return e;
        *secs = tp.tv_sec;
        *nanos = tp.tv_nsec;
        return 0;
    }

    int sys_execve(const char *path, char *const argv[], char *const envp[]) {
        auto ret = __syscall3(SYS_execve, (long)path, (long)argv, (long)envp);
        if (int e = sc_error(ret); e)
            return e;
        return 0;
    }

    int sys_fork(pid_t *child) {
        fflush(stdout);
        auto ret = __syscall2(SYS_clone, SIGCHLD, 0);
        if (int e = sc_error(ret); e)
            return e;
        *child = (pid_t)ret;
        return 0;
    }

    int sys_access(const char *path, int mode) {
        auto ret = __syscall2(SYS_access, (long)path, mode);
        if (int e = sc_error(ret); e)
            return e;
        return 0;
    }

    int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
        auto ret = __syscall4(SYS_wait4, pid, (long)status, flags, (long)ru);
        if (int e = sc_error(ret); e)
            return e;
        *ret_pid = (pid_t)ret;
        return 0;
    }

    int sys_open_dir(const char *path, int *fd) {
        return sys_open(path, O_DIRECTORY, 0, fd);
    }

    int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
        auto ret = __syscall3(SYS_getdents64, handle, (long)buffer, max_size);
        if (int e = sc_error(ret); e)
            return e;
        *bytes_read = ret;
        return 0;
    }

    int sys_getpid() {
        return __syscall0(SYS_getpid);
    }

    [[gnu::weak]] int sys_rename(const char *path, const char *new_path) {
        auto ret = __syscall2(82 /* SYS_rename */, (long)path, (long)new_path);
        return sc_error(ret);
    }

    int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
        if (!act) {
            auto ret = __syscall4(SYS_rt_sigaction, signum, 0, (long)oldact, 8);
            return sc_error(ret);
        }
        
        return ENOSYS;
    }

    int sys_sigprocmask(int how, const sigset_t *set, sigset_t *old) {
        auto ret = __syscall4(SYS_rt_sigprocmsk, how, (long)set, (long)old, NSIG / 8);
        if (int e = sc_error(ret); e)
            return e;
        return 0;
    }

    uid_t sys_getuid() {
        return __syscall0(SYS_getuid);
    }

    gid_t sys_getgid() {
        return __syscall0(SYS_getgid);
    }

    gid_t sys_geteuid() {
        return __syscall0(SYS_geteuid);
    }

    gid_t sys_getegid() {
        return __syscall0(SYS_getegid);
    }

    int sys_gethostname(char *name, size_t len) {
        if (!name)
            return -EFAULT;
        if (!len)
            return -EINVAL;

        struct utsname uname;
        auto ret = __syscall1(SYS_uname, (long)&uname);
        if (int e = sc_error(ret); e) {
            return e;
        }

        size_t size = strlen(uname.nodename);
        if (len <= size)
            return -ENAMETOOLONG;
        
        strcpy(name, uname.nodename);
        return 0;
    }

    int sys_sethostname(const char *buffer, size_t bufsize) {
        auto ret = __syscall2(SYS_sethostname, (long)buffer, bufsize);
        if (int e = sc_error(ret); e)
            return e;
        return 0;
    }

    int sys_uname(struct utsname *buf) {
        auto ret = __syscall1(SYS_uname, (long)buf);
        if (int e = sc_error(ret); e)
            return e;
        return 0;
    }

    pid_t sys_getppid() {
        return __syscall0(SYS_getppid);
    }

    int sys_getpgid(pid_t pid, pid_t *pgid) {
        if (!pgid)
            return EINVAL;

        auto ret = __syscall1(SYS_getpgid, pid);
        if (int e = sc_error(ret); e)
            return e;
        *pgid = ret;
        return 0;
    }

    int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
        auto ret = __syscall4(257 /* SYS_openat */, dirfd, (long)path, flags, mode);
        if (int e = sc_error(ret); e)
            return e;
        *fd = (int)ret;
        return 0;
    }

    int sys_dup(int fd, int flags, int *newfd) {
        auto ret = __syscall1(SYS_dup, fd);
        if (int e = sc_error(ret); e)
            return e;
        *newfd = ret;
        return 0;
    }

    int sys_setpgid(pid_t pid, pid_t pgid) {
        auto ret = __syscall2(109 /* SYS_setpgid */, pid, pgid);
        if (int e = sc_error(ret); e)
            return e;
        return 0;
    }

    int sys_tcgetpgrp(int fd, pid_t *pgid) {
        auto ret = __syscall3(SYS_ioctl, fd, 0x540F /* TIOCGPGRP */, (long)pgid);
        return sc_error(ret);
    }

    int sys_tcsetpgrp(int fd, pid_t pgid) {
        auto ret = __syscall3(SYS_ioctl, fd, 0x5410 /* TIOCSPGRP */, (long)&pgid);
        return sc_error(ret);
    }

    int sys_fcntl(int fd, int cmd, va_list args, int *result) {
        return 0;
    }

    int sys_tcgetattr(int fd, struct termios *attrs) {
        return 0;
    }

    int sys_tcsetattr(int fd, int optional_actions, const struct termios *attrs) {
        return 0;
    }

    #define TIOCGNAME   0x5483

    int sys_ttyname(int fd, char *buf, size_t size) {
        int ret;
        sys_ioctl(fd, TIOCGNAME, buf, &ret);
        return 0;
    }

} //namespace mlibc

extern "C" { 
    void *__dso_handle __attribute__((visibility("hidden"))) = nullptr;
}