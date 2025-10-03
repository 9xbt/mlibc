#include "mlibc/ansi-sysdeps.hpp"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <fcntl.h>

#include <asm/ioctls.h>
#include <abi-bits/seek-whence.h>
#include <abi-bits/vm-flags.h>
#include <abi-bits/signal.h>
#include <abi-bits/ioctls.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <abi-bits/stat.h>
#include <mlibc/fsfd_target.hpp>
#include <mlibc/all-sysdeps.hpp>

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
        return -__syscall1(SYS_set_tls, (long)pointer);
    }

    [[gnu::weak]] int sys_futex_tid() {
        return __syscall0(SYS_gettid);
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
        return -__syscall2(SYS_munmap, (long)pointer, size);
    }

    int sys_anon_allocate(size_t size, void **pointer) {
        return sys_vm_map(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, pointer);
    }

    int sys_anon_free(void *pointer, size_t size) {
        return sys_vm_unmap(pointer, size);
    }

    int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
        auto ret = __syscall4(SYS_openat, AT_FDCWD, (long)pathname, flags, mode);
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
        return -__syscall1(SYS_close, fd);
    }

    void sys_exit(int status) {
        __syscall1(SYS_exit, status);
        __builtin_unreachable();
    }

    int sys_clock_get(int clock, time_t *secs, long *nanos) {
        return -ENOSYS;
    }

    int sys_isatty(int fd) {
        char _[8];
        auto ret = __syscall3(SYS_ioctl, fd, TIOCGWINSZ, (long)_);
        if (ret < 0)
            return 1;
        return 0;
    }

    pid_t sys_getpid() {
        return __syscall0(SYS_getpid);
    }

    pid_t sys_gettid() {
        return __syscall0(SYS_gettid);
    }

    pid_t sys_getppid() {
        return __syscall0(SYS_getppid);
    }

    pid_t sys_getpgid(pid_t pid, pid_t *pgid) {
        *pgid = 0;
        return 0;
    }

    int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
        if (fsfdt == fsfd_target::path)
            fd = AT_FDCWD;
        else if (fsfdt == fsfd_target::fd)
            flags |= AT_EMPTY_PATH;

        return -__syscall4(SYS_fstatat, fd, (long)path, (long)statbuf, flags);
    }

    int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
        auto ret = __syscall3(SYS_ioctl, fd, request, (long)arg);
        if (ret < 0)
            return -ret;
        *result = ret;
        return 0;
    }

    int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
        return 0;
    }

    int sys_sigaction(int how, const struct sigaction *__restrict action, struct sigaction *__restrict old_action) {
        return 0;
    }

    int sys_ttyname(int fd, char *buf, size_t size) {
        strcpy(buf, "/dev/console");
        return 0;
    }

    int sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
        *ruid = 0;
        *euid = 0;
        *suid = 0;
        return 0;
    }
    
    int sys_getresgid(uid_t *rgid, uid_t *egid, uid_t *sgid) {
        *rgid = 0;
        *egid = 0;
        *sgid = 0;
        return 0;
    }

    int sys_fork(pid_t *child) {
        auto ret = __syscall0(SYS_fork);
        if (ret < 0)
            return -ret;
        *child = ret;
        return 0;
    }

    int sys_execve(const char *path, char *const argv[], char *const envp[]) {
        return -__syscall3(SYS_exec, (long)path, (long)argv, (long)envp);
    }

    int sys_uname(struct utsname *buf) {
        return -__syscall1(SYS_uname, (long)buf);
    }

    int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
        auto ret = __syscall3(SYS_waitpid, pid, (long)status, flags);
        if (ret < 0)
            return -ret;
        *ret_pid = ret;
        return 0;
    }

    int sys_gethostname(char *buf, size_t bufsize) {
        struct utsname utsname;
        auto ret = __syscall1(SYS_uname, (long)&utsname);
        if (ret < 0)
            return -ret;
        strncpy(buf, utsname.nodename, bufsize);
        return 0;
    }

    int sys_getcwd(char *buf, size_t size) {
        strncpy(buf, "/", size);
        return 0;
    }

    int sys_dup(int fd, int flags, int *newfd) {
        auto ret = __syscall3(SYS_dup, fd, -1, flags);
        if (ret < 0)
            return -ret;
        *newfd = ret;
        return 0;
    }

    int sys_dup2(int fd, int flags, int newfd) {
        auto ret = __syscall3(SYS_dup, fd, newfd, flags);
        if (ret < 0)
            return -ret;
        return 0;
    }

    int sys_tcgetattr(int fd, struct termios *attr) {
        auto ret = __syscall3(SYS_ioctl, fd, TCGETS, (long)attr);
        if (ret < 0)
            return -ret;
        return 0;
    }

    int sys_fcntl(int fd, int request, va_list args, int *result) {
        auto arg = va_arg(args, unsigned long);
        auto ret = __syscall3(SYS_fcntl, fd, request, arg);
        if (ret < 0)
            return -ret;
        *result = ret;
        return 0;
    }

    int sys_open_dir(const char *path, int *fd) {
        return sys_open(path, O_DIRECTORY, 0, fd);
    }

    int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
        auto ret = __syscall3(SYS_readdir, handle, (long)buffer, max_size);
        if (ret < 0)
            return ret;
        *bytes_read = ret;
        return 0;
    }

} //namespace mlibc

extern "C" { 
    void *__dso_handle __attribute__((visibility("hidden"))) = nullptr;
}
