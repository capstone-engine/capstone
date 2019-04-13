#ifndef CS_FUZZ_PLATFORM_H
#define CS_FUZZ_PLATFORM_H

struct platform {
    cs_arch arch;
    cs_mode mode;
    const char *comment;
    const char *cstoolname;
};

#endif
