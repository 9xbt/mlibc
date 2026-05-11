#include <sys/mman.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <bits/ensure.h>
#include <mlibc/tcb.hpp>

extern "C" void __mlibc_thread_trampoline(void *(*fn)(void *), Tcb *tcb, void *arg) {
	mlibc::sys_tcb_set(tcb);

	while(__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED) == 0)
		mlibc::sys_futex_wait(&tcb->tid, 0, nullptr);

	tcb->invokeThreadFunc(reinterpret_cast<void *>(fn), arg);

	__atomic_store_n(&tcb->didExit, 1, __ATOMIC_RELEASE);
	mlibc::sys_futex_wake(&tcb->didExit);

	mlibc::sys_thread_exit();
}