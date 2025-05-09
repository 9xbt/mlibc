#pragma once
#include <stddef.h>

size_t __syscall0(size_t rax) {
    size_t ret;
    asm volatile (
        "syscall"
        : "=a" (ret)
        : "a" (rax)
        : "rcx", "r11"
    );
    return ret;
}

size_t __syscall1(size_t rax, size_t rdi) {
    size_t ret;
    asm volatile (
        "syscall"
        : "=a" (ret)
        : "a" (rax), "D" (rdi)
        : "rcx", "r11"
    );
    return ret;
}

size_t __syscall2(size_t rax, size_t rdi, size_t rsi) {
    size_t ret;
    asm volatile (
        "syscall"
        : "=a" (ret)
        : "a" (rax), "D" (rdi), "S" (rsi)
        : "rcx", "r11"
    );
    return ret;
}

size_t __syscall3(size_t rax, size_t rdi, size_t rsi, size_t rdx) {
    size_t ret;
    asm volatile (
        "syscall"
        : "=a" (ret)
        : "a" (rax), "D" (rdi), "S" (rsi), "d" (rdx)
        : "rcx", "r11"
    );
    return ret;
}

size_t __syscall4(size_t rax, size_t rdi, size_t rsi, size_t rdx, size_t r10) {
    size_t ret;
    asm volatile (
        "mov %5, %%r10\n"
        "syscall"
        : "=a"(ret)
        : "a"(rax), "D"(rdi), "S"(rsi), "d"(rdx), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

size_t __syscall5(size_t rax, size_t rdi, size_t rsi, size_t rdx, size_t r10, size_t r8) {
    size_t ret;
    asm volatile (
        "mov %5, %%r10\n"
        "mov %6, %%r8\n"
        "syscall"
        : "=a"(ret)
        : "a"(rax), "D"(rdi), "S"(rsi), "d"(rdx), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory"
    );
    return ret;
}

size_t __syscall6(size_t rax, size_t rdi, size_t rsi, size_t rdx, size_t r10, size_t r8, size_t r9) {
    size_t ret;
    asm volatile (
        "mov %5, %%r10\n"
        "mov %6, %%r8\n"
        "mov %7, %%r9\n"
        "syscall"
        : "=a"(ret)
        : "a"(rax), "D"(rdi), "S"(rsi), "d"(rdx),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}
