#include <sys/mman.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <bits/ensure.h>
#include <mlibc/tcb.hpp>

extern "C" void __mlibc_thread_trampoline(void *(*fn)(void *), Tcb *tcb, void *arg) {
	mlibc::sysdep<mlibc::TcbSet>(tcb);

	while(__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED) == 0)
		mlibc::sysdep<mlibc::FutexWait>(&tcb->tid, 0, nullptr);

	tcb->invokeThreadFunc(reinterpret_cast<void *>(fn), arg);

	__atomic_store_n(&tcb->didExit, 1, __ATOMIC_RELEASE);
	mlibc::sysdep<mlibc::FutexWake>(&tcb->didExit, false);

	mlibc::sysdep<mlibc::ThreadExit>();
}