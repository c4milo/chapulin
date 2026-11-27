# shellcheck shell=bash
# The ch_cfg.cpu value a caller on this CPU would state, and the names of
# a value's bits. bench/primitives.sh and bench/inplace.sh source this
# file, after they set ARCH to arm64 or x86_64 and BENCH_NAME to the name
# their failure messages give. It sources bench/neoverse.sh.
# shellcheck source=bench/neoverse.sh
. bench/neoverse.sh

# The bits of ch_cfg.cpu (cpu_cfg.h).
CPU_PROBED=0x1
CPU_CONSTANT_TIME_AES=0x2
CPU_CONSTANT_TIME_MULTIPLY=0x4
CPU_AVX2=0x8
CPU_VAES=0x10
CPU_CONSTANT_TIME_SHA256=0x20
CPU_CONSTANT_TIME_SHA512=0x40
CPU_CONSTANT_TIME_SHA3=0x80
CPU_AVX512_IFMA=0x100
CPU_AVX512=0x200
CPU_BMI2_ADX=0x400
CPU_BMI1=0x800
CPU_SVE2=0x1000
CPU_CONSTANT_TIME_EOR3=0x2000

# Whether a CPU's feature list names every word given.
reports() { # $1 = the list, space separated; the rest = the words
    local features=" $1 " word
    shift
    for word in "$@"; do
        case "$features" in
        *" $word "*) ;;
        *) return 1 ;;
        esac
    done
}

# The ch_cfg.cpu value a caller on this CPU would state: CH_CPU_PROBED, the
# multiply bit, the AES bit where the CPU reports the AES instructions and
# the carry-less multiply, the SHA-256 bit where it reports the SHA-256
# instructions, on arm64 the SHA-512 bit where it reports the SHA-512
# instructions, the SHA-3 bit and the EOR3 bit where it reports the SHA-3
# ones, but the EOR3 bit alone on an Arm Neoverse N2, and on
# x86-64 the AVX2 and VAES bits where it reports those, the IFMA bit
# where it reports AVX-512F and AVX-512 IFMA, and CH_CPU_AVX512 where it
# reports AVX-512F, AVX-512BW, AVX-512VL, VAES and VPCLMULQDQ, and on arm64
# CH_CPU_SVE2 where it reports SVE2. A program gcc
# built holds no Keccak on the SHA-3 instructions, and there the SHA-3
# bit picks nothing (docs/decisions.md 99). BENCH_CPU from the
# environment wins, for a system this function has no probe for. The
# six timing bits also state that the instructions run in constant time
# in the thread's mode. The bench sets
# no such mode, neither PSTATE.DIT nor DOITM: it times the paths the bits
# pick and states nothing a deployment could rely on.
cpu_value() {
    if [ -n "${BENCH_CPU:-}" ]; then
        printf '0x%x\n' "$((BENCH_CPU))"
        return
    fi
    local features="" value=$((CPU_PROBED | CPU_CONSTANT_TIME_MULTIPLY))
    case "$(uname -s) $ARCH" in
    "Darwin arm64")
        # macOS names each feature in a sysctl of its own; the words below
        # are the ones arm64 Linux gives the same features.
        if [ "$(sysctl -n hw.optional.arm.FEAT_AES 2>/dev/null)" = 1 ] &&
            [ "$(sysctl -n hw.optional.arm.FEAT_PMULL 2>/dev/null)" = 1 ]; then
            features="aes pmull"
        fi
        if [ "$(sysctl -n hw.optional.arm.FEAT_SHA256 2>/dev/null)" = 1 ]; then
            features="$features sha2"
        fi
        if [ "$(sysctl -n hw.optional.arm.FEAT_SHA512 2>/dev/null)" = 1 ]; then
            features="$features sha512"
        fi
        if [ "$(sysctl -n hw.optional.arm.FEAT_SHA3 2>/dev/null)" = 1 ]; then
            features="$features sha3"
        fi
        if [ "$(sysctl -n hw.optional.arm.FEAT_SVE2 2>/dev/null)" = 1 ]; then
            features="$features sve2"
        fi
        ;;
    "Linux arm64") features=$(sed -n 's/^Features[[:space:]]*: //p' /proc/cpuinfo | head -1) ;;
    "Linux x86_64") features=$(sed -n 's/^flags[[:space:]]*: //p' /proc/cpuinfo | head -1) ;;
    *)
        echo "FAIL ${BENCH_NAME:-bench} bench: no probe here for this system's CPU; state BENCH_CPU," \
            "the ch_cfg.cpu value a caller on it would" >&2
        exit 1
        ;;
    esac
    if reports "$features" aes pmull || reports "$features" aes pclmulqdq; then
        value=$((value | CPU_CONSTANT_TIME_AES))
    fi
    # arm64 Linux names FEAT_SHA256 sha2, and x86-64 Linux the SHA
    # extensions sha_ni, which the bit names with SSSE3 and SSE4.1.
    if { [ "$ARCH" = arm64 ] && reports "$features" sha2; } ||
        { [ "$ARCH" = x86_64 ] && reports "$features" sha_ni ssse3 sse4_1; }; then
        value=$((value | CPU_CONSTANT_TIME_SHA256))
    fi
    # arm64 Linux names FEAT_SHA512 sha512. An x86-64 object refuses the
    # bit.
    if [ "$ARCH" = arm64 ] && reports "$features" sha512; then
        value=$((value | CPU_CONSTANT_TIME_SHA512))
    fi
    # arm64 Linux names FEAT_SHA3 sha3. An x86-64 object refuses both bits.
    # On an Arm Neoverse N2 a caller states EOR3 alone and leaves the SHA-3
    # bit clear (bench/neoverse.sh, docs/decisions.md 244).
    if [ "$ARCH" = arm64 ] && reports "$features" sha3; then
        value=$((value | CPU_CONSTANT_TIME_EOR3))
        if ! neoverse_n2; then
            value=$((value | CPU_CONSTANT_TIME_SHA3))
        fi
    fi
    if [ "$ARCH" = x86_64 ] && reports "$features" avx2; then
        value=$((value | CPU_AVX2))
        if reports "$features" vaes vpclmulqdq; then
            value=$((value | CPU_VAES))
        fi
    fi
    # x86-64 Linux names AVX-512F avx512f and AVX-512 IFMA avx512ifma. A
    # CPU can have the first without the second, so the probe asks for
    # both.
    if [ "$ARCH" = x86_64 ] && reports "$features" avx512f avx512ifma; then
        value=$((value | CPU_AVX512_IFMA))
    fi
    # The 512-bit AES-GCM kernel's: x86-64 Linux names AVX-512BW avx512bw
    # and AVX-512VL avx512vl.
    if [ "$ARCH" = x86_64 ] && reports "$features" avx512f avx512bw avx512vl vaes vpclmulqdq; then
        value=$((value | CPU_AVX512))
    fi
    # x25519_adx.c's and p256_adx_field.c's: x86-64 Linux names BMI2 bmi2
    # and ADX adx.
    if [ "$ARCH" = x86_64 ] && reports "$features" bmi2 adx; then
        value=$((value | CPU_BMI2_ADX))
    fi
    # sha3_hw.c's x86-64 copy, which runs beside CH_CPU_BMI2_ADX: x86-64
    # Linux names BMI1 bmi1.
    if [ "$ARCH" = x86_64 ] && reports "$features" bmi1; then
        value=$((value | CPU_BMI1))
    fi
    # chacha20_sve2.c's copy: arm64 Linux names SVE2 sve2. macOS would name
    # it FEAT_SVE2, which macOS 26 does not define.
    if [ "$ARCH" = arm64 ] && reports "$features" sve2; then
        value=$((value | CPU_SVE2))
    fi
    printf '0x%x\n' "$value"
}

# The names of the bits a value holds, for the CSV's header. Each word of
# the list names one variable above and the bit of cpu_cfg.h it stands for.
cpu_names() { # $1 = a ch_cfg.cpu value
    local names=CH_CPU_PROBED bit variable
    for bit in CONSTANT_TIME_AES CONSTANT_TIME_MULTIPLY AVX2 VAES CONSTANT_TIME_SHA256 \
        CONSTANT_TIME_SHA512 CONSTANT_TIME_SHA3 AVX512_IFMA AVX512 BMI2_ADX BMI1 SVE2 \
        CONSTANT_TIME_EOR3; do
        variable=CPU_$bit
        if [ $(($1 & ${!variable})) -ne 0 ]; then
            names="$names, CH_CPU_$bit"
        fi
    done
    printf '%s\n' "$names"
}
