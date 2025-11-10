#include "mlibc/posix-sysdeps.hpp"
#include <stddef.h>
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

    int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
        auto ret = __syscall4(SYS_openat, dirfd, (long)path, flags, mode);
        if (ret < 0)
            return -ret;
        *fd = ret;
        return 0;
    }

    int sys_open(const char *path, int flags, mode_t mode, int *fd) {
        return sys_openat(AT_FDCWD, path, flags, mode, fd);
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
        struct timespec ts;
        auto ret = __syscall2(SYS_gettime, clock, (long)&ts);
        if (ret < 0)
            return -ret;
        *secs = ts.tv_sec;
        *nanos = ts.tv_nsec;
        return 0;
    }

    int sys_isatty(int fd) {
        char _[8];
        auto ret = __syscall3(SYS_ioctl, fd, TIOCGWINSZ, (long)_);
        if (ret < 0)
            return ENOTTY;
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
        auto ret = __syscall1(SYS_getpgid, pid);
        if (ret < 0)
            return -ret;
        *pgid = ret;
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

    int sys_sigaction(int how, const struct sigaction *__restrict action, struct sigaction *__restrict old_action) {
        return -__syscall3(SYS_sigaction, how, (long)action, (long)old_action);
    }

    int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
        return -__syscall3(SYS_sigprocmask, how, (long)set, (long)retrieve);
    }

    int sys_ttyname(int fd, char *buf, size_t size) {
        strcpy(buf, "/dev/tty1");
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
        return -__syscall2(SYS_getcwd, (long)buf, size);
    }

    int sys_chdir(const char *path) {
        return - __syscall1(SYS_chdir, (long)path);
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
            return -ret;
        *bytes_read = ret;
        return 0;
    }

    int sys_setpgid(pid_t pid, pid_t pgid) {
        return -__syscall2(SYS_setpgid, pid, pgid);
    }

    int sys_pipe(int *fds, int flags) {
        return -__syscall2(SYS_pipe, (long)fds, flags);
    }

    int sys_sysconf(int num, long *ret) {
        // respectfully shut the fuck up
        switch (num) {
            case _SC_OPEN_MAX:
                *ret = 256;
                break;
            case _SC_CHILD_MAX:
                *ret = 25;
                break;
            case _SC_LINE_MAX:
                *ret = 2048;
                break;
            default:
                return EINVAL;
        }
        return 0;
    }

    int sys_tcsetattr(int fd, int op, const struct termios *attr) {
        switch (op) {
            case TCSANOW:
                op = TCSETS;
                break;
            case TCSADRAIN:
                op = TCSETSW;
                break;
            case TCSAFLUSH:
                op = TCSETSF;
                break;
            default:
                return EINVAL;
        }

        return -__syscall3(SYS_ioctl, fd, op, (long)attr);
    }

    int sys_pselect(int num_fds, fd_set *read_set, fd_set *write_set, fd_set *except_set, const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
        struct pollfd fds[num_fds];
        for (int i = 0; i < num_fds; i++) {
            fds[i].fd = i;
            fds[i].events = 0;
            fds[i].revents = 0;

            if (read_set && FD_ISSET(i, read_set))
                fds[i].events |= POLLIN;
            if (write_set && FD_ISSET(i, write_set))
                fds[i].events |= POLLOUT;
            if (except_set && FD_ISSET(i, except_set))
                fds[i].events |= POLLPRI;
        }

        auto ret = __syscall5(SYS_ppoll, (long)fds, (long)num_fds, (long)timeout, (long)sigmask, sizeof(*sigmask));
        if (ret < 0)
            return -ret;

        if (read_set) FD_ZERO(read_set);
        if (write_set) FD_ZERO(write_set);
        if (except_set) FD_ZERO(except_set);

        for (int i = 0; i < num_fds; i++) {
            if (fds[i].revents & POLLIN && read_set)
                FD_SET(i, read_set);
            if (fds[i].revents & POLLOUT && write_set)
                FD_SET(i, write_set);
            if (fds[i].revents & POLLPRI && except_set) 
                FD_SET(i, except_set);
        }
        *num_events = ret;
        return 0;
    }

    int sys_sleep(time_t *sec, long *nanosec) {
        struct timespec ts = {
            .tv_sec = *sec,
            .tv_nsec = *nanosec
        };
        return -__syscall1(SYS_sleep, (long)&ts);
    }

    uid_t sys_getuid() {
        return 0;
    }

    uid_t sys_geteuid() {
        return 0;
    }
    
    int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {
        return -__syscall4(SYS_faccessat, dirfd, (long)pathname, mode, flags);
    }

    int sys_unlinkat(int dirfd, const char *path, int flags) {
        return -__syscall3(SYS_unlinkat, dirfd, (long)path, flags);
    }

    int sys_mkdir(const char *path, mode_t mode) {
        return -__syscall3(SYS_mkdirat, AT_FDCWD, (long)path, mode);
    }

    int sys_mkdirat(int dirfd, const char *path, mode_t mode) {
        return -__syscall3(SYS_mkdirat, dirfd, (long)path, mode);
    }

    int sys_rmdir(const char *path) {
        return sys_unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
    }
    
    int sys_socket(int family, int type, int protocol, int *fd) {
        auto ret = __syscall3(SYS_socket, family, type, protocol);
        if (ret < 0)
            return -ret;
        *fd = ret;
        return 0;
    }

    int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
        return -__syscall3(SYS_bind, fd, (long)addr_ptr, addr_length);
    }

    int sys_listen(int fd, int backlog) {
        return -__syscall2(SYS_listen, fd, backlog);
    }

    int sys_connect(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
        return -__syscall3(SYS_connect, fd, (long)addr_ptr, addr_length);
    }

    int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length, int flags) {
        (void)flags;
        auto ret = __syscall3(SYS_accept, fd, (long)addr_ptr, (long)addr_length);
        if (ret < 0)
            return -ret;
        *newfd = ret;
        return 0;
    }

    ssize_t sys_sendto(int fd, const void *buffer, size_t size, int flags, const struct sockaddr *sock_addr, socklen_t addr_length, ssize_t *length) {
        auto ret = __syscall6(SYS_sendto, fd, (long)buffer, size, flags, (long)sock_addr, (long)addr_length);
        if (ret < 0)
            return -ret;
        *length = ret;
        return 0;
    }

    ssize_t sys_recvfrom(int fd, void *buffer, size_t size, int flags, struct sockaddr *sock_addr, socklen_t *addr_length, ssize_t *length) {
        auto ret = __syscall6(SYS_recvfrom, fd, (long)buffer, size, flags, (long)sock_addr, (long)addr_length);
        if (ret < 0)
            return -ret;
        *length = ret;
        return 0;
    }

    int sys_msg_send(int fd, const struct msghdr *hdr, int flags, ssize_t *length) {
        ssize_t len = 0;
        for (size_t i = 0; i < hdr->msg_iovlen; i++) {
            const auto &iov = hdr->msg_iov[i];
            ssize_t chunk_len;
            
            if (auto ret = sys_sendto(fd, iov.iov_base, iov.iov_len, flags, (const sockaddr *)hdr->msg_name, hdr->msg_namelen, &chunk_len); ret != 0)
                return ret;
            
            len += chunk_len;
            if ((size_t)chunk_len < iov.iov_len)
                break;
        }
        
        *length = len;
        return 0;
    }

    int sys_msg_recv(int fd, struct msghdr *hdr, int flags, ssize_t *length) {
        ssize_t len = 0;
        for (size_t i = 0; i < hdr->msg_iovlen; i++) {
            auto &iov = hdr->msg_iov[i];
            ssize_t chunk_len;
            
            if (auto ret = sys_recvfrom(fd, iov.iov_base, iov.iov_len, flags, (sockaddr *)hdr->msg_name, &hdr->msg_namelen, &chunk_len); ret != 0)
                return ret;
            
            len += chunk_len;
            if ((size_t)chunk_len < iov.iov_len)
                break;
        }
        
        *length = len;
        return 0;
    }

    int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
        struct timespec ts = {
            .tv_sec = timeout / 1000,
            .tv_nsec = (timeout % 1000) * 1000000
        };
        auto ret = __syscall5(SYS_ppoll, (long)fds, (long)count, timeout > 0 ? (long)&ts : 0, 0, 0);
        if (ret < 0)
            return -ret;
        *num_events = ret;
        return 0;
    }

    int sys_kill(int pid, int sig) {
        return -__syscall2(SYS_kill, pid, sig);
    }

    int sys_sethostname(const char *buffer, size_t bufsize) {
        return -__syscall2(SYS_hostname, (long)buffer, bufsize);
    }

    int sys_tcflow(int fd, int action) {
        return -__syscall3(SYS_ioctl, fd, TCXONC, action);
    }

    int sys_access(const char *path, int mode) {
        return sys_faccessat(AT_FDCWD, path, mode, 0);
    }

    int sys_fchdir(int fd) {
        return -__syscall1(SYS_fchdir, fd);
    }

    int sys_timer_create(clockid_t clk, struct sigevent *__restrict evp, timer_t *__restrict res) {
        return 0;
    }

    int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) {
        return 0;
    }

    int sys_timer_settime(timer_t t, int flags, const struct itimerspec *__restrict val, struct itimerspec *__restrict old) {
        return 0;
    }

    int sys_sigpending(sigset_t *set) {
        return 0;
    }

    int sys_fsync(int fd) {
        return 0;
    }

    int sys_renameat(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
        return -__syscall4(SYS_renameat, olddirfd, (long)old_path, newdirfd, (long)new_path);
    }

    int sys_rename(const char *path, const char *new_path) {
        return sys_renameat(AT_FDCWD, path, AT_FDCWD, new_path);
    }

    int sys_readlinkat(int dirfd, const char *path, void *buffer, size_t max_size, ssize_t *length) {
        auto ret = __syscall4(SYS_readlinkat, dirfd, (long)path, (long)buffer, max_size);
        if (ret < 0)
            return -ret;
        *length = ret;
        return 0;
    }

    int sys_readlink(const char *path, void *buffer, size_t max_size, ssize_t *length) {
        return sys_readlinkat(AT_FDCWD, path, buffer, max_size, length);
    }

    int sys_symlinkat(const char *target_path, int dirfd, const char *link_path) {
        return -__syscall3(SYS_symlinkat, (long)target_path, dirfd, (long)link_path);
    }

    int sys_symlink(const char *target_path, const char *link_path) {
        return sys_symlinkat(target_path, AT_FDCWD, link_path);
    }

} //namespace mlibc

extern "C" { 
    void *__dso_handle __attribute__((visibility("hidden"))) = nullptr;
}
