#ifndef _ABIBITS_SIGSET_T_H
#define _ABIBITS_SIGSET_T_H

typedef struct {
	unsigned long __sig[(65 + 8 * sizeof(unsigned long) - 1) / (8 * sizeof(unsigned long))];
} sigset_t;

#endif /* _ABIBITS_SIGSET_T_H */
