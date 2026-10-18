//! The Zig API's Cpu: what the caller states about its CPU in a host object, and the ch_cfg.cpu
//! value it gives, which chapulin.zig declares as chapulin.Cpu and chapulin.cpuBits. It sits in a
//! file of its own because chapulin.zig stood at the 500-line cap CLAUDE.md sets and make lint-size
//! holds. docs/zig.md is the reference.
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

// A host object: each session states what the caller found about its CPU in ch_cfg (cpu_cfg.h).
const has_cpu = @hasField(c.ch_cfg, "cpu");

/// ch_cfg.cpu in a host object (cpu_cfg.h): what the caller's own probe found, and what it states.
/// A value sets CH_CPU_PROBED and the bit of each field that is true.
pub const Cpu = if (has_cpu) CpuBits else @compileError("Cpu needs a host object: TRUST=webpki, ROLE=server or ROLE=both on arm64 or x86-64");
const CpuBits = struct {
    /// CH_CPU_CONSTANT_TIME_AES: the AES and carry-less multiply instructions, which the caller
    /// states run in constant time in the mode the session's thread runs in.
    constant_time_aes: bool = false,
    /// CH_CPU_CONSTANT_TIME_MULTIPLY: the caller states the widening multiply runs in constant time,
    /// and the session runs the native multiply in place of ct.h's 16x16 decomposition, and X25519
    /// on the 51-bit-word field. On x86-64 the statement covers AVX-512 IFMA's 52-bit products too,
    /// which avx512_ifma runs beside this bit.
    constant_time_multiply: bool = false,
    /// CH_CPU_AVX2: the CPU has AVX2 and its operating system saves the 256-bit registers, and the
    /// session's ChaCha20 keystream runs in 256-bit vectors. Without avx512_ifma the session also
    /// runs RSA verification's public operation on rsa_avx2.c's 28-bit digits, or 27-bit above
    /// 3,072 bits, four to a 256-bit register, for the moduli avx512_ifma names. An x86-64 bit,
    /// which an arm64 object refuses.
    avx2: bool = false,
    /// CH_CPU_VAES: the CPU also has VAES and VPCLMULQDQ on those registers, and beside
    /// constant_time_aes AES-GCM's whole blocks run two to a register. An x86-64 bit as well.
    vaes: bool = false,
    /// CH_CPU_CONSTANT_TIME_SHA256: the SHA-256 instructions, which the caller states run in
    /// constant time in that mode: FEAT_SHA256 on arm64, and on x86-64 the SHA extensions with
    /// SSSE3 and SSE4.1. The session then hashes its transcript and derives its keys over SHA-256
    /// on them.
    constant_time_sha256: bool = false,
    /// CH_CPU_CONSTANT_TIME_SHA512: the SHA-512 instructions, FEAT_SHA512, under the same
    /// statement. An arm64 bit, which an x86-64 object refuses. Under TLS_AES_256_GCM_SHA384 the
    /// session then hashes its transcript and derives its keys over SHA-384 on them.
    constant_time_sha512: bool = false,
    /// CH_CPU_CONSTANT_TIME_SHA3: the SHA-3 instructions, FEAT_SHA3, under the same statement. An
    /// arm64 bit as well. The session then runs ML-KEM's hashes on them, in an object that clang
    /// compiled, as `zig build` does.
    constant_time_sha3: bool = false,
    /// CH_CPU_AVX512_IFMA: the CPU has AVX-512F and AVX-512 IFMA and its operating system saves
    /// the opmask and 512-bit registers. It states presence alone, as avx2 does, and with it the
    /// session runs RSA verification's public operation on rsa_ifma.c's 52-bit digits, eight to
    /// a 512-bit register, for an odd modulus of 2,048 bits or more whose bit length is a multiple
    /// of 64, and its ChaCha20 keystream sixteen blocks a pass on chacha20_avx512.c in place of
    /// avx2's kernel. Beside constant_time_multiply the session also signs with RSA on
    /// rsa_ifma_sign.c and runs a Poly1305 update of 512 bytes or more on poly1305_ifma.c. x509.c's
    /// chain links under TRUST=ca-rsa run rsa_mont64.c whatever this says. An x86-64 bit, which an
    /// arm64 object refuses.
    avx512_ifma: bool = false,
    /// CH_CPU_AVX512: the CPU has AVX-512F, AVX-512BW and AVX-512VL, and VAES and VPCLMULQDQ on
    /// the 512-bit registers, and its operating system saves the opmask and 512-bit registers. It
    /// states presence alone, as avx2 does. Beside vaes and constant_time_aes the session runs each
    /// AES-GCM seal and open whole, four blocks to a 512-bit register, on gcm_avx512_kernel.c. It
    /// picks nothing else, so a caller can leave it clear and keep avx512_ifma's kernels. An
    /// x86-64 bit, which an arm64 object refuses.
    avx512: bool = false,
};

/// ch_cfg.cpu for what found states, and 0 for null, which every init refuses. EcdsaP256Key.fromPem
/// passes it to ch_p256_key_from_pem too.
pub const cpuBits = if (has_cpu) cpuBitsOf else @compileError("cpuBits needs a host object: TRUST=webpki, ROLE=server or ROLE=both on arm64 or x86-64");
fn cpuBitsOf(found: ?CpuBits) u32 {
    const cpu = found orelse return 0;
    return c.CH_CPU_PROBED | (if (cpu.constant_time_aes) c.CH_CPU_CONSTANT_TIME_AES else 0) |
        (if (cpu.constant_time_multiply) c.CH_CPU_CONSTANT_TIME_MULTIPLY else 0) |
        (if (cpu.avx2) c.CH_CPU_AVX2 else 0) | (if (cpu.vaes) c.CH_CPU_VAES else 0) |
        (if (cpu.constant_time_sha256) c.CH_CPU_CONSTANT_TIME_SHA256 else 0) |
        (if (cpu.constant_time_sha512) c.CH_CPU_CONSTANT_TIME_SHA512 else 0) |
        (if (cpu.constant_time_sha3) c.CH_CPU_CONSTANT_TIME_SHA3 else 0) |
        (if (cpu.avx512_ifma) c.CH_CPU_AVX512_IFMA else 0) |
        (if (cpu.avx512) c.CH_CPU_AVX512 else 0);
}
