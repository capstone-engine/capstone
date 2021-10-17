//
// Created by phosphorus on 8/19/21.
//

#ifndef CAPSTONE_LOGGER_H
#define CAPSTONE_LOGGER_H

//#define CAPSTONE_NG_DEBUG
//#define TO_FILE "/home/phosphorus/Capstone/start.log"

#ifdef CAPSTONE_NG_DEBUG

#ifdef TO_FILE

#define init_file freopen(TO_FILE, "w+", stdout); \
    setvbuf(stdout, NULL, _IONBF, 0)

#else

#define init_file {}

#endif

#define debug(format, ...) printf("[DEBUG] " format __VA_OPT__(,) __VA_ARGS__)

#define debugln(format, ...) printf("[DEBUG] " format "\n" __VA_OPT__(,) __VA_ARGS__)

#define println(format, ...) printf(format "\n" __VA_OPT__(,) __VA_ARGS__)


#else

#define init_file {}

#define debug(format, ...) {}

#define debugln(format, ...) {}

#define println(format, ...) {}

#endif

#endif //CAPSTONE_LOGGER_H
