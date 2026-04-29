// =============================================================================
// Pagewise.cpp - SEH-guarded page copy implementation
// =============================================================================
//
// The whole file's reason to exist is the four-line __try block below.
// Everything else is scaffolding to keep MSVC's "no C++ destructors in
// __try scope" rule happy: only POD locals, no std::string, no RAII
// wrappers, no exception-throwing constructors.
//
// We can't even have a CRITICAL_SECTION guard object in scope - it's
// got a destructor. The function is leaf-pure: takes plain pointers,
// copies bytes, returns a bool. Anything that needs synchronization or
// logging is the caller's job.
// =============================================================================

#include "Pagewise.h"

#include <cstring>
#include <windows.h>

namespace ENI::Dumper {

bool ReadPageSEH(void* dst, const void* src, std::size_t len) {
    // `volatile` so the compiler doesn't decide the pre-__try store is
    // dead and reorder it past the __try barrier. We need this value
    // observable from the __except branch.
    volatile bool ok = false;
    __try {
        std::memcpy(dst, src, len);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

} // namespace ENI::Dumper
