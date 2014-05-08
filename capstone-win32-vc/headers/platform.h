#pragma once

#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)
    #define strcasecmp _stricmp
#endif
