#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
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
#include <mlibc/debug.hpp>

#include <syscall.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace mlibc {
    void Sysdeps<LibcLog>::operator()(const char *message) {
        __syscall3(SYS_write, 2, (long)message, strlen(message));
        __syscall3(SYS_write, 2, (long)"\n", 1);
    }

    [[noreturn]] void Sysdeps<LibcPanic>::operator()() {
        __syscall3(SYS_write, 2, (long)"\n", 1);
        __syscall1(SYS_exit, 1);
        __builtin_unreachable();
    }

    int Sysdeps<TcbSet>::operator()(void *pointer) {
        return -__syscall1(SYS_set_tls, (long)pointer);
    }

    pid_t Sysdeps<FutexTid>::operator()() {
        return __syscall0(SYS_gettid);
    }

    int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const struct timespec *time) {
        return -__syscall3(SYS_futex_wait, (long)pointer, expected, (long)time);
    }

    int Sysdeps<FutexWake>::operator()(int *pointer, bool all) {
        return -__syscall2(SYS_futex_wake, (long)pointer, all ? INT_MAX : 1);
    }

    int Sysdeps<VmMap>::operator()(void *hint, size_t size, int prot, int flags,
            int fd, off_t offset, void **window) {
        auto ret = __syscall6(SYS_mmap, (long)hint, (long)size, (long)prot,
                (long)flags, (long)fd, (long)offset);
        if (ret < 0)
            return -ret;
        *window = (void *)ret;
        return 0;
    }

    int Sysdeps<VmUnmap>::operator()(void *pointer, size_t size) {
        return -__syscall2(SYS_munmap, (long)pointer, size);
    }

    int Sysdeps<VmProtect>::operator()(void *pointer, size_t size, int prot) {
        return -__syscall3(SYS_mprotect, (long)pointer, size, prot);
    }

    int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
        return sysdep<VmMap>(nullptr, size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, pointer);
    }

    int Sysdeps<AnonFree>::operator()(void *pointer, size_t size) {
        return sysdep<VmUnmap>(pointer, size);
    }

    int Sysdeps<Openat>::operator()(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
        auto ret = __syscall4(SYS_openat, dirfd, (long)path, flags, mode);
        if (ret < 0)
            return -ret;
        *fd = ret;
        return 0;
    }

    int Sysdeps<Open>::operator()(const char *path, int flags, mode_t mode, int *fd) {
        return sysdep<Openat>(AT_FDCWD, path, flags, mode, fd);
    }

    int Sysdeps<Read>::operator()(int fd, void *buf, size_t len, ssize_t *bytes_read) {
        auto ret = __syscall3(SYS_read, fd, (long)buf, len);
        if (ret < 0)
            return -ret;
        *bytes_read = ret;
        return 0;
    }

    int Sysdeps<Write>::operator()(int fd, const void *buf, size_t len, ssize_t *bytes_written) {
        auto ret = __syscall3(SYS_write, fd, (long)buf, len);
        if (ret < 0)
            return -ret;
        *bytes_written = ret;
        return 0;
    }

    int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
        auto ret = __syscall3(SYS_seek, fd, offset, whence);
        if (ret < 0)
            return -ret;
        *new_offset = ret;
        return 0;
    }

    int Sysdeps<Close>::operator()(int fd) {
        return -__syscall1(SYS_close, fd);
    }

    [[noreturn]] void Sysdeps<Exit>::operator()(int status) {
        __syscall1(SYS_exit, status);
        __builtin_unreachable();
    }

    int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
        struct timespec ts;
        auto ret = __syscall2(SYS_gettime, clock, (long)&ts);
        if (ret < 0)
            return -ret;
        *secs = ts.tv_sec;
        *nanos = ts.tv_nsec;
        return 0;
    }

    int Sysdeps<Sleep>::operator()(time_t *sec, long *nanosec) {
        struct timespec ts = {
            .tv_sec = *sec,
            .tv_nsec = *nanosec
        };
        return -__syscall1(SYS_sleep, (long)&ts);
    }

    uid_t Sysdeps<GetUid>::operator()() {
        return 0;
    }

    uid_t Sysdeps<GetEuid>::operator()() {
        return 0;
    }

    gid_t Sysdeps<GetGid>::operator()() {
        return 0;
    }

    gid_t Sysdeps<GetEgid>::operator()() {
        return 0;
    }

    int Sysdeps<SetUid>::operator()(uid_t uid) {
        (void)uid;
        return 0;
    }

    int Sysdeps<SetGid>::operator()(gid_t gid) {
        (void)gid;
        return 0;
    }

    int Sysdeps<Isatty>::operator()(int fd) {
        char _[8];
        auto ret = __syscall3(SYS_ioctl, fd, TIOCGWINSZ, (long)_);
        if (ret < 0)
            return ENOTTY;
        return 0;
    }

    int Sysdeps<Tcgetattr>::operator()(int fd, struct termios *attr) {
        auto ret = __syscall3(SYS_ioctl, fd, TCGETS, (long)attr);
        if (ret < 0)
            return -ret;
        return 0;
    }

    int Sysdeps<Tcsetattr>::operator()(int fd, int op, const struct termios *attr) {
        switch(op) {
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

    int Sysdeps<Tcflow>::operator()(int fd, int action) {
        return -__syscall3(SYS_ioctl, fd, TCXONC, action);
    }

    int Sysdeps<Tcgetwinsize>::operator()(int fd, struct winsize *winsz) {
        return -__syscall3(SYS_ioctl, fd, TIOCGWINSZ, (long)winsz);
    }

    int Sysdeps<Tcsetwinsize>::operator()(int fd, const struct winsize *winsz) {
        return -__syscall3(SYS_ioctl, fd, TIOCSWINSZ, (long)winsz);
    }

    pid_t Sysdeps<GetPid>::operator()() {
        return __syscall0(SYS_getpid);
    }

    pid_t Sysdeps<GetTid>::operator()() {
        return __syscall0(SYS_gettid);
    }

    pid_t Sysdeps<GetPpid>::operator()() {
        return __syscall0(SYS_getppid);
    }

    int Sysdeps<GetPgid>::operator()(pid_t pid, pid_t *pgid) {
        auto ret = __syscall1(SYS_getpgid, pid);
        if (ret < 0)
            return -ret;
        *pgid = ret;
        return 0;
    }

    int Sysdeps<SetPgid>::operator()(pid_t pid, pid_t pgid) {
        return -__syscall2(SYS_setpgid, pid, pgid);
    }

    int Sysdeps<SetSid>::operator()(pid_t *sid) {
        auto ret = -__syscall0(SYS_setsid);
        if (ret < 0)
            return ret;
        *sid = ret;
        return 0;
    }

    int Sysdeps<Stat>::operator()(mlibc::fsfd_target fsfdt, int fd, const char *path,
            int flags, struct stat *statbuf) {
        switch(fsfdt) {
            case fsfd_target::path:
                return -__syscall4(SYS_fstatat, AT_FDCWD, (long)path, (long)statbuf, 0);
            case fsfd_target::fd:
                return -__syscall4(SYS_fstatat, fd, (long)"", (long)statbuf, AT_EMPTY_PATH);
            case fsfd_target::fd_path:
                return -__syscall4(SYS_fstatat, fd, (long)path, (long)statbuf, flags);
            default:
                return ENOSYS;
        }
    }

    int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *arg, int *result) {
        auto ret = __syscall3(SYS_ioctl, fd, request, (long)arg);
        if (ret < 0)
            return -ret;
        if (result)
            *result = ret;
        return 0;
    }

    int Sysdeps<Sigaction>::operator()(int how, const struct sigaction *__restrict action,
            struct sigaction *__restrict old_action) {
        return -__syscall3(SYS_sigaction, how, (long)action, (long)old_action);
    }

    int Sysdeps<Sigprocmask>::operator()(int how, const sigset_t *__restrict set,
            sigset_t *__restrict retrieve) {
        return -__syscall3(SYS_sigprocmask, how, (long)set, (long)retrieve);
    }

    int Sysdeps<GetResuid>::operator()(uid_t *ruid, uid_t *euid, uid_t *suid) {
        *ruid = 0;
        *euid = 0;
        *suid = 0;
        return 0;
    }

    int Sysdeps<GetResgid>::operator()(gid_t *rgid, gid_t *egid, gid_t *sgid) {
        *rgid = 0;
        *egid = 0;
        *sgid = 0;
        return 0;
    }

    int Sysdeps<Fork>::operator()(pid_t *child) {
        auto ret = __syscall0(SYS_fork);
        if (ret < 0)
            return -ret;
        *child = ret;
        return 0;
    }

    int Sysdeps<Execve>::operator()(const char *path, char *const argv[], char *const envp[]) {
        return -__syscall3(SYS_exec, (long)path, (long)argv, (long)envp);
    }

    int Sysdeps<Uname>::operator()(struct utsname *buf) {
		return -__syscall1(SYS_uname, (long)buf);
	}

    int Sysdeps<Waitpid>::operator()(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
        auto ret = __syscall3(SYS_waitpid, pid, (long)status, flags);
        if (ret < 0)
            return -ret;
        *ret_pid = ret;
        return 0;
    }

    int Sysdeps<GetCwd>::operator()(char *buf, size_t size) {
        return -__syscall2(SYS_getcwd, (long)buf, size);
    }

    int Sysdeps<Chdir>::operator()(const char *path) {
        return -__syscall1(SYS_chdir, (long)path);
    }

    int Sysdeps<Fchdir>::operator()(int fd) {
        return -__syscall1(SYS_fchdir, fd);
    }

    int Sysdeps<Dup>::operator()(int fd, int flags, int *newfd) {
        auto ret = __syscall3(SYS_dup, fd, -1, flags);
        if (ret < 0)
            return -ret;
        *newfd = ret;
        return 0;
    }

    int Sysdeps<Dup2>::operator()(int fd, int flags, int newfd) {
        auto ret = __syscall3(SYS_dup, fd, newfd, flags);
        if (ret < 0)
            return -ret;
        return 0;
    }

    int Sysdeps<Fcntl>::operator()(int fd, int request, va_list args, int *result) {
        auto arg = va_arg(args, unsigned long);
        auto ret = __syscall3(SYS_fcntl, fd, request, arg);
        if (ret < 0)
            return -ret;
        *result = ret;
        return 0;
    }

    int Sysdeps<OpenDir>::operator()(const char *path, int *handle) {
        return sysdep<Open>(path, O_DIRECTORY, 0, handle);
    }

    int Sysdeps<ReadEntries>::operator()(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
        auto ret = __syscall3(SYS_readdir, handle, (long)buffer, max_size);
        if (ret < 0)
            return -ret;
        *bytes_read = ret;
        return 0;
    }

    int Sysdeps<Pipe>::operator()(int *fds, int flags) {
        return -__syscall2(SYS_pipe, (long)fds, flags);
    }

    int Sysdeps<GetRlimit>::operator()(int resource, struct rlimit *limit) {
        return -__syscall2(SYS_getrlimit, resource, (long)limit);
    }

    int Sysdeps<Sysconf>::operator()(int num, long *ret) {
        struct rlimit ru;
        switch(num) {
            case _SC_OPEN_MAX:
                if (int e = sysdep<GetRlimit>(RLIMIT_NOFILE, &ru); e)
                    return e;
                *ret = (ru.rlim_cur == RLIM_INFINITY) ? -1 : ru.rlim_cur;
                break;
            case _SC_CHILD_MAX:
                if (int e = sysdep<GetRlimit>(RLIMIT_NPROC, &ru); e)
                    return e;
                *ret = (ru.rlim_cur == RLIM_INFINITY) ? -1 : ru.rlim_cur;
                break;
            case _SC_LINE_MAX:
                *ret = 2048;
                break;
            default:
                return EINVAL;
        }
        return 0;
    }

    int Sysdeps<Faccessat>::operator()(int dirfd, const char *pathname, int mode, int flags) {
        return -__syscall4(SYS_faccessat, dirfd, (long)pathname, mode, flags);
    }

    int Sysdeps<Access>::operator()(const char *path, int mode) {
        return sysdep<Faccessat>(AT_FDCWD, path, mode, 0);
    }

    int Sysdeps<Unlinkat>::operator()(int dirfd, const char *path, int flags) {
        return -__syscall3(SYS_unlinkat, dirfd, (long)path, flags);
    }

    int Sysdeps<Mkdir>::operator()(const char *path, mode_t mode) {
        return -__syscall3(SYS_mkdirat, AT_FDCWD, (long)path, mode);
    }

    int Sysdeps<Mkdirat>::operator()(int dirfd, const char *path, mode_t mode) {
        return -__syscall3(SYS_mkdirat, dirfd, (long)path, mode);
    }

    int Sysdeps<Rmdir>::operator()(const char *path) {
        return sysdep<Unlinkat>(AT_FDCWD, path, AT_REMOVEDIR);
    }

    int Sysdeps<Socket>::operator()(int family, int type, int protocol, int *fd) {
        auto ret = __syscall3(SYS_socket, family, type, protocol);
        if (ret < 0)
            return -ret;
        *fd = ret;
        return 0;
    }

    int Sysdeps<Bind>::operator()(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
        return -__syscall3(SYS_bind, fd, (long)addr_ptr, addr_length);
    }

    int Sysdeps<Listen>::operator()(int fd, int backlog) {
        return -__syscall2(SYS_listen, fd, backlog);
    }

    int Sysdeps<Connect>::operator()(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
        return -__syscall3(SYS_connect, fd, (long)addr_ptr, addr_length);
    }

    int Sysdeps<Accept>::operator()(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length, int flags) {
        (void)flags;
        auto ret = __syscall3(SYS_accept, fd, (long)addr_ptr, (long)addr_length);
        if (ret < 0)
            return -ret;
        *newfd = ret;
        return 0;
    }

    int Sysdeps<Sendto>::operator()(int fd, const void *buffer, size_t size, int flags,
            const struct sockaddr *sock_addr, socklen_t addr_length, ssize_t *length) {
        auto ret = __syscall6(SYS_sendto, fd, (long)buffer, size, flags, (long)sock_addr, (long)addr_length);
        if (ret < 0)
            return -ret;
        *length = ret;
        return 0;
    }

    int Sysdeps<Recvfrom>::operator()(int fd, void *buffer, size_t size, int flags,
            struct sockaddr *sock_addr, socklen_t *addr_length, ssize_t *length) {
        auto ret = __syscall6(SYS_recvfrom, fd, (long)buffer, size, flags, (long)sock_addr, (long)addr_length);
        if (ret < 0)
            return -ret;
        *length = ret;
        return 0;
    }

    int Sysdeps<MsgSend>::operator()(int fd, const struct msghdr *hdr, int flags, ssize_t *length) {
        auto ret = __syscall3(SYS_sendmsg, fd, (long)hdr, flags);
        if (ret < 0)
            return -ret;
        *length = ret;
        return 0;
    }

    int Sysdeps<MsgRecv>::operator()(int fd, struct msghdr *hdr, int flags, ssize_t *length) {
        auto ret = __syscall3(SYS_recvmsg, fd, (long)hdr, flags);
        if (ret < 0)
            return -ret;
        *length = ret;
        return 0;
    }

    int Sysdeps<Shutdown>::operator()(int sockfd, int how) {
        return -__syscall2(SYS_shutdown, sockfd, how);
    }

    int Sysdeps<Poll>::operator()(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
        struct timespec ts = {
            .tv_sec = timeout / 1000,
            .tv_nsec = (timeout % 1000) * 1000000
        };
        auto ret = __syscall5(SYS_ppoll, (long)fds, (long)count,
                timeout == -1 ? 0 : (long)&ts, 0, 0);
        if (ret < 0)
            return -ret;
        *num_events = ret;
        return 0;
    }

    int Sysdeps<Kill>::operator()(pid_t pid, int sig) {
        return -__syscall2(SYS_kill, pid, sig);
    }

    int Sysdeps<SetHostname>::operator()(const char *buffer, size_t bufsize) {
        return -__syscall2(SYS_sethostname, (long)buffer, bufsize);
    }

    int Sysdeps<TimerCreate>::operator()(clockid_t clk, struct sigevent *__restrict evp, timer_t *__restrict res) {
        return 0;
    }

    int Sysdeps<SetItimer>::operator()(int which, const struct itimerval *new_value, struct itimerval *old_value) {
        return 0;
    }

    int Sysdeps<TimerSettime>::operator()(timer_t t, int flags, const struct itimerspec *__restrict val, struct itimerspec *__restrict old) {
        return 0;
    }

    int Sysdeps<Sigpending>::operator()(sigset_t *set) {
        return 0;
    }

    int Sysdeps<Fsync>::operator()(int fd) {
        return 0;
    }

    int Sysdeps<Renameat>::operator()(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
        return -__syscall4(SYS_renameat, olddirfd, (long)old_path, newdirfd, (long)new_path);
    }

    int Sysdeps<Rename>::operator()(const char *path, const char *new_path) {
        return sysdep<Renameat>(AT_FDCWD, path, AT_FDCWD, new_path);
    }

    int Sysdeps<Readlinkat>::operator()(int dirfd, const char *path, void *buffer, size_t max_size, ssize_t *length) {
        auto ret = __syscall4(SYS_readlinkat, dirfd, (long)path, (long)buffer, max_size);
        if (ret < 0)
            return -ret;
        *length = ret;
        return 0;
    }

    int Sysdeps<Readlink>::operator()(const char *path, void *buffer, size_t max_size, ssize_t *length) {
        return sysdep<Readlinkat>(AT_FDCWD, path, buffer, max_size, length);
    }

    int Sysdeps<Symlinkat>::operator()(const char *target_path, int dirfd, const char *link_path) {
        return -__syscall3(SYS_symlinkat, (long)target_path, dirfd, (long)link_path);
    }

    int Sysdeps<Symlink>::operator()(const char *target_path, const char *link_path) {
        return sysdep<Symlinkat>(target_path, AT_FDCWD, link_path);
    }

    int Sysdeps<Umask>::operator()(mode_t mode, mode_t *old) {
        auto ret = __syscall1(SYS_umask, mode);
        if (ret < 0)
            return -ret;
        *old = ret;
        return 0;
    }

    int Sysdeps<Fchmod>::operator()(int fd, mode_t mode) {
        return -__syscall2(SYS_fchmod, fd, mode);
    }

    int Sysdeps<Fchmodat>::operator()(int fd, const char *pathname, mode_t mode, int flags) {
        return -__syscall4(SYS_chmodat, fd, (long)pathname, mode, flags);
    }

    int Sysdeps<Chmod>::operator()(const char *pathname, mode_t mode) {
        return sysdep<Fchmodat>(AT_FDCWD, pathname, mode, 0);
    }

    [[noreturn]] void Sysdeps<ThreadExit>::operator()() {
        __syscall0(SYS_exit_thread);
        __builtin_unreachable();
    }

    int Sysdeps<Linkat>::operator()(int olddirfd, const char *old_path, int newdirfd, const char *new_path, int flags) {
        return -__syscall5(SYS_linkat, olddirfd, (long)old_path, newdirfd, (long)new_path, flags);
    }

    int Sysdeps<Link>::operator()(const char *old_path, const char *new_path) {
        return sysdep<Linkat>(AT_FDCWD, old_path, AT_FDCWD, new_path, 0);
    }

    int Sysdeps<GetSockopt>::operator()(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict size) {
        return -__syscall5(SYS_getsockopt, fd, layer, number, (long)buffer, (long)size);
    }

    int Sysdeps<Readv>::operator()(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_read) {
        auto ret = __syscall3(SYS_readv, fd, (long)iovs, iovc);
        if (ret < 0)
            return -ret;
        *bytes_read = ret;
        return 0;
    }

    int Sysdeps<Writev>::operator()(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_written) {
        auto ret = __syscall3(SYS_writev, fd, (long)iovs, iovc);
        if (ret < 0)
            return -ret;
        *bytes_written = ret;
        return 0;
    }

    int Sysdeps<Unlockpt>::operator()(int fd) {
        int unlock = 0;
        return sysdep<Ioctl>(fd, TIOCSPTLCK, &unlock, nullptr);
    }

    int Sysdeps<PrepareStack>::operator()(void **stack, void *entry, void *arg,
        void *tcb, size_t *stack_size, size_t *guard_size, void **stack_base) {
        *guard_size = 0;
        *stack_size = *stack_size ? *stack_size : 0x100000;

        if (!*stack) {
            if (int e = sysdep<VmMap>(NULL, *stack_size, PROT_READ | PROT_WRITE,MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, stack_base); e)
                return e;
        } else *stack_base = *stack;

        *stack = (void *)((char *)*stack_base + *stack_size);

		void **sp = (void **)*stack;
		*--sp = arg;
		*--sp = tcb;
		*--sp = entry;
		*stack = (void *)sp;

        return 0;
    }

    int Sysdeps<Fadvise>::operator()(int fd, off_t offset, off_t length, int advice) {
        return 0;
    }

    #ifndef MLIBC_BUILDING_RTLD

    int Sysdeps<Ptsname>::operator()(int fd, char *buffer, size_t length) {
        int pty_num;
        if (int e = sysdep<Ioctl>(fd, TIOCGPTN, &pty_num, nullptr); e)
            return e;

        snprintf(buffer, length, "/dev/pts/%d", pty_num);
        return 0;
    }

    int Sysdeps<Ttyname>::operator()(int fd, char *buf, size_t size) {
        strcpy(buf, "/dev/tty1");
        return 0;
    }

    int Sysdeps<GetHostname>::operator()(char *buf, size_t bufsize) {
        struct utsname utsname;
        auto ret = __syscall1(SYS_uname, (long)&utsname);
        if (ret < 0)
            return -ret;
        strncpy(buf, utsname.nodename, bufsize);
        return 0;
    }

    int Sysdeps<Pselect>::operator()(int num_fds, fd_set *read_set, fd_set *write_set,
            fd_set *except_set, const struct timespec *timeout,
            const sigset_t *sigmask, int *num_events) {
        struct pollfd fds[num_fds];
        int count = 0;

        for (int i = 0; i < num_fds; i++) {
            short events = 0;
            if (read_set && FD_ISSET(i, read_set))
                events |= POLLIN;
            if (write_set && FD_ISSET(i, write_set))
                events |= POLLOUT;
            if (except_set && FD_ISSET(i, except_set))
                events |= POLLPRI;
            if (!events)
                continue;

            fds[count] = (struct pollfd){ .fd = i, .events = events, .revents = 0 };
            count++;
        }

        auto ret = __syscall5(SYS_ppoll, (long)fds, (long)count, (long)timeout, (long)sigmask, sizeof(*sigmask));
        if (ret < 0)
            return -ret;

        if (read_set) FD_ZERO(read_set);
        if (write_set) FD_ZERO(write_set);
        if (except_set) FD_ZERO(except_set);

        for (int i = 0; i < count; i++) {
            if (fds[i].revents & POLLIN && read_set)
                FD_SET(fds[i].fd, read_set);
            if (fds[i].revents & POLLOUT && write_set)
                FD_SET(fds[i].fd, write_set);
            if (fds[i].revents & POLLPRI && except_set)
                FD_SET(fds[i].fd, except_set);
        }
        *num_events = ret;
        return 0;
    }

    extern "C" void __mlibc_thread_entry();

    int Sysdeps<Clone>::operator()(void *tcb, pid_t *pid_out, void *stack) {
        (void)tcb;
        auto ret = __syscall2(SYS_clone, (long)__mlibc_thread_entry, (long)stack);
        if (ret < 0)
            return -ret;
        *pid_out = ret;
        return 0;
    }

    int Sysdeps<GetEntropy>::operator()(void *buffer, size_t length) {
        int fd;
        if (int e = sysdep<Open>("/dev/urandom", O_RDONLY, 0, &fd); e)
            mlibc::panicLogger() << "/dev/urandom open error " << strerror(e) << frg::endlog;

        ssize_t bytes;
        if (int e = sysdep<Read>(fd, buffer, length, &bytes); e) {
            mlibc::infoLogger() << "/dev/urandom read error " << strerror(e) << frg::endlog;
            return e;
        }

        sysdep<Close>(fd);
        return 0;
    }

    #endif // !MLIBC_BUILDING_RTLD

} // namespace mlibc

#pragma GCC diagnostic pop