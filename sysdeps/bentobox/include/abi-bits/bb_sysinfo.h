#ifndef _ABIBITS_BB_SYSINFO_H
#define _ABIBITS_BB_SYSINFO_H

#include <stddef.h>

struct bb_sysinfo {
    size_t totalram;
    size_t freeram;
    size_t nprocs_onln;
};

#endif /* _ABIBITS_BB_SYSINFO_H */
