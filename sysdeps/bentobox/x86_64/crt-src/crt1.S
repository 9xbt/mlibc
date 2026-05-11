.section .text
.global _start
.extern __mlibc_entry
_start:
	mov %rsp, %rdi
	lea main(%rip), %rsi
	call __mlibc_entry