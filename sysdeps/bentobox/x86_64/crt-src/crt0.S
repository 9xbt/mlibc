.section .text
.global _start
.extern __mlibc_entry
_start:
	# FIXME (bentobox)
	mov %rsp, %rdi
	lea main(%rip), %rsi
	call __mlibc_entry

.section .note.GNU-stack,"",%progbits

