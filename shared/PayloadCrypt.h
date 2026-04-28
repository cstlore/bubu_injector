#pragma once

// =============================================================================
// PayloadCrypt.h - on-disk format for the encrypted payload
// =============================================================================
//
// Why this exists: bin/payload.bin used to be a verbatim copy of the
// payload DLL. An analyst with file-system access could pick it up cold,
// run dumpbin / strings / IDA against it, and see every string, every
// import, every function name. We want the disk artifact to look like
// random noise until the shim decrypts it in memory.
//
// Threat model: we are NOT trying to keep the key secret from someone
// who already has the shim DLL. The key is per-build, baked into the
// shim binary, and a determined analyst with both files can extract it
// trivially. What we ARE trying to do:
//
//   * Stop "drag-and-drop into IDA" cold analysis of payload.bin.
//   * Stop signature-based AV scanning of the payload at rest. The
//     ciphertext has zero entropy resemblance to the plaintext PE.
//   * Make the shim's role visible only to someone who's already deep
//     enough in our chain to be reading shim source - at which point
//     they can read the payload too anyway.
//
// Cipher: ChaCha20 (RFC 7539). Stream cipher, no auth tag. The mapper
// validates the PE structure post-decrypt and fails loudly on garbage,
// which serves as a coarse integrity check - a flipped ciphertext bit
// produces an invalid PE header within 64 bytes of decrypt.
//
// Note: the original sketch in TODO #10 specified a 16-byte nonce. We
// went with the RFC 7539 12-byte standard instead - one fewer byte on
// disk, more testable against any reference implementation, and the
// extra 4 bytes of nonce buys us nothing because the key is per-build
// (we never reuse a key across two encrypted payloads).
//
// On-disk format:
//
//   +--------+------------------+--------------------+
//   | magic  | nonce (12 bytes) | ciphertext (rest)  |
//   +--------+------------------+--------------------+
//     4 B       12 B              variable
//
// The ciphertext length equals the original payload size; ChaCha20 is a
// stream cipher so no padding.
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ENI::Crypt {

// "ENIE" little-endian = 0x45494E45. Distinct from ENI::Boot::Magic
// (ENIB) and ENI::Shim::Magic (ENIS) so a corrupted hand-off is
// recognizable in a hex editor.
constexpr std::uint32_t PayloadMagic = 0x45494E45;

constexpr std::size_t KeyBytes   = 32;  // ChaCha20 key
constexpr std::size_t NonceBytes = 12;  // RFC 7539 nonce
constexpr std::size_t HeaderBytes = sizeof(std::uint32_t) + NonceBytes;

// The build-time symmetric key. Replaced by tools/encrypt_payload.py at
// build time via a generated PayloadKey.h - DO NOT edit this default
// directly; rebuilds will overwrite it. The default here is a placeholder
// of 0xAA bytes so dev builds without the key-generation step still
// produce something consumable, while production builds get a unique
// 32-byte key per build embedded into the shim binary.
//
// The key is in a constexpr array rather than a string literal so it
// doesn't end up scannable as ASCII; rodata sections still hold it but
// at least `strings` won't catch it.
struct KeyMaterial {
    std::uint8_t Bytes[KeyBytes];
};

// We define this header-only as `inline constexpr` so multiple TUs
// linking PayloadCrypt.h don't trip ODR. The actual contents are
// supplied by the generated PayloadKey.h when the build system has run
// the keygen step; otherwise fall back to the development placeholder.
#if __has_include("PayloadKey.h")
#include "PayloadKey.h"
#else
inline constexpr KeyMaterial PayloadKey = {{
    // Development placeholder - production replaces this via PayloadKey.h.
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
}};
#endif

// -----------------------------------------------------------------------------
// ChaCha20 (RFC 7539) - reference implementation
// -----------------------------------------------------------------------------
//
// Kept short and readable rather than fast - we run it once at shim init
// over a few hundred KB. A hand-tuned vectorized version would be
// pointless overkill here. The structure follows RFC 7539 §2.3 exactly:
//
//   * 16-word state: 4 constants ("expand 32-byte k") + 8 key words +
//     1 counter word + 3 nonce words.
//   * 20 rounds = 10 double-rounds, each is 4 column rounds + 4 diagonal
//     rounds.
//   * Output keystream block = state + initial_state, little-endian.
//   * XOR keystream into plaintext to produce ciphertext (and vice
//     versa - it's a stream cipher).

namespace detail {

constexpr std::uint32_t Rotl32(std::uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

inline void QuarterRound(std::uint32_t& a, std::uint32_t& b,
                         std::uint32_t& c, std::uint32_t& d) {
    a += b; d ^= a; d = Rotl32(d, 16);
    c += d; b ^= c; b = Rotl32(b, 12);
    a += b; d ^= a; d = Rotl32(d,  8);
    c += d; b ^= c; b = Rotl32(b,  7);
}

inline std::uint32_t LoadLE32(const std::uint8_t* p) {
    return  static_cast<std::uint32_t>(p[0])        |
           (static_cast<std::uint32_t>(p[1]) <<  8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

inline void StoreLE32(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >>  8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

inline void Block(const std::uint8_t key[32], std::uint32_t counter,
                  const std::uint8_t nonce[12], std::uint8_t out[64]) {
    // Constants spell "expand 32-byte k" little-endian.
    std::uint32_t state[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        LoadLE32(key +  0), LoadLE32(key +  4), LoadLE32(key +  8), LoadLE32(key + 12),
        LoadLE32(key + 16), LoadLE32(key + 20), LoadLE32(key + 24), LoadLE32(key + 28),
        counter,
        LoadLE32(nonce + 0), LoadLE32(nonce + 4), LoadLE32(nonce + 8),
    };

    std::uint32_t working[16];
    std::memcpy(working, state, sizeof(working));

    for (int i = 0; i < 10; i++) {
        // Column rounds
        QuarterRound(working[0], working[4], working[ 8], working[12]);
        QuarterRound(working[1], working[5], working[ 9], working[13]);
        QuarterRound(working[2], working[6], working[10], working[14]);
        QuarterRound(working[3], working[7], working[11], working[15]);
        // Diagonal rounds
        QuarterRound(working[0], working[5], working[10], working[15]);
        QuarterRound(working[1], working[6], working[11], working[12]);
        QuarterRound(working[2], working[7], working[ 8], working[13]);
        QuarterRound(working[3], working[4], working[ 9], working[14]);
    }

    for (int i = 0; i < 16; i++) {
        StoreLE32(out + 4 * i, working[i] + state[i]);
    }
}

} // namespace detail

// In-place XOR-stream encrypt/decrypt. ChaCha20 is symmetric - the same
// function does both operations. `data` is modified in place; counter
// starts at 1 per RFC 7539 (block 0 is reserved for Poly1305 keying in
// the AEAD construction, which we don't use - but we follow convention
// so any third-party verifier can re-derive identical ciphertext).
inline void ApplyKeystream(const std::uint8_t key[32],
                           const std::uint8_t nonce[12],
                           std::uint8_t* data, std::size_t len) {
    std::uint8_t block[64];
    std::uint32_t counter = 1;
    std::size_t offset = 0;

    while (offset < len) {
        detail::Block(key, counter, nonce, block);
        const std::size_t chunk = (len - offset) < 64 ? (len - offset) : 64;
        for (std::size_t i = 0; i < chunk; i++) {
            data[offset + i] ^= block[i];
        }
        offset += chunk;
        counter++;
    }
}

// Convenience: decrypt a payload.bin blob in place, return true if the
// magic header matched. On success, `data` contains the plaintext PE
// starting at offset 0 (the header + nonce are dropped from the front
// by the caller via the outSize/outBuffer split below).
//
// Layout reminder:
//   bytes [0..4)     - magic
//   bytes [4..16)    - nonce
//   bytes [16..end)  - ciphertext
//
// Returns:
//   true  + plaintextOut populated  on a valid blob
//   false + plaintextOut untouched  on bad magic / short input
inline bool TryDecryptPayload(const std::uint8_t* blob, std::size_t blobSize,
                              std::uint8_t* plaintextOut, std::size_t plaintextCap,
                              std::size_t* plaintextSize) {
    if (blobSize < HeaderBytes) return false;

    std::uint32_t magic = 0;
    std::memcpy(&magic, blob, sizeof(magic));
    if (magic != PayloadMagic) return false;

    const std::size_t cipherSize = blobSize - HeaderBytes;
    if (cipherSize > plaintextCap) return false;

    std::memcpy(plaintextOut, blob + HeaderBytes, cipherSize);
    ApplyKeystream(PayloadKey.Bytes, blob + sizeof(magic),
                   plaintextOut, cipherSize);

    if (plaintextSize) *plaintextSize = cipherSize;
    return true;
}

} // namespace ENI::Crypt
