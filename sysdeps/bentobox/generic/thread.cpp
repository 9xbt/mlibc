#include <sys/mman.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <bits/ensure.h>
#include <mlibc/tcb.hpp>

extern "C" void __mlibc_thread_trampoline(void *(*fn)(void *), Tcb *tcb, void *arg) {
	mlibc::sysdep<TcbSet>(tcb);

	while(__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED) == 0)
		mlibc::sysdep<FutexWait>(&tcb->tid, 0, nullptr);

	__atomic_fetch_or(&tcb->cancelBits, tcbCancelEnableBit, __ATOMIC_RELAXED);
	tcb->invokeThreadFunc(reinterpret_cast<void *>(fn), arg);

	mlibc::thread_exit(tcb->returnValue);
}