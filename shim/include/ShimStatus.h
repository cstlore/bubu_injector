#pragma once

// Shim error codes returned from ENIShimEntry. Kept tiny so the launcher
// can map them to log lines without dragging in another header.

#include <cstdint>

namespace ENI::Shim {

enum class Status : std::uint32_t {
    Ok = 0,

    // Envelope validation
    InvalidEnvelope = 1,    // Magic / version / size mismatch
    PayloadNotFound = 2,    // ShimEnvelope.PayloadPath couldn't be read

    // Hook installation
    KernelHandleFailed = 10,    // GetModuleHandleW(L"kernel32.dll") returned null
    GetProcAddressFailed = 11,  // CreateProcessW / ResumeThread not found
    ProtectFailed = 12,         // VirtualProtect on the function prologue failed
    HookAlreadyInstalled = 13,  // We already hooked - shouldn't happen, defensive

    // Internal
    OutOfMemory = 20,
    InternalLogicError = 99,
};

constexpr const char* StatusToString(Status s) {
    switch (s) {
        case Status::Ok:                     return "Ok";
        case Status::InvalidEnvelope:        return "InvalidEnvelope";
        case Status::PayloadNotFound:        return "PayloadNotFound";
        case Status::KernelHandleFailed:     return "KernelHandleFailed";
        case Status::GetProcAddressFailed:   return "GetProcAddressFailed";
        case Status::ProtectFailed:          return "ProtectFailed";
        case Status::HookAlreadyInstalled:   return "HookAlreadyInstalled";
        case Status::OutOfMemory:            return "OutOfMemory";
        case Status::InternalLogicError:     return "InternalLogicError";
    }
    return "Unknown";
}

} // namespace ENI::Shim
