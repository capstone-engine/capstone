#if defined(_MSC_VER) && _MSC_VER <= 1700
#include "msvc/headers/inttypes.h"
#elif defined(CAPSTONE_HAS_OSXKERNEL)
#include "osxkernel_inttypes.h" /* this is a trimmed copy of system inttypes.h that doesn't exit in kernel framework headers */
#else
#include <inttypes.h>
#endif
