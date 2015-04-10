#if defined(_MSC_VER) && _MSC_VER <= 1700
#include "msvc/headers/inttypes.h"
#elif defined(CAPSTONE_HAS_OSXKERNEL)
/* this is a trimmed copy of system inttypes.h that doesn't exist
in OSX kernel framework headers */
#include "osxkernel_inttypes.h"
#else
#include <inttypes.h>
#endif
