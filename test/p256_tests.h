// The ECDSA P-256 verify vectors: one RFC 6979 key, three good
// signatures, and the mutations and out-of-range scalars that must be
// refused. Included by test/unit_test.c only, after its CHECK macro and
// unhex helper.
#ifndef CH_P256_TESTS_H
#define CH_P256_TESTS_H

// ECDSA P-256/SHA-256 verify. Key and the "sample"/"test" signatures are
// RFC 6979 A.2.5; the third signature is project-computed with a fixed k
// and cross-checked with `openssl dgst -sha256 -verify`. Hashes are
// SHA-256 of the named message.
static void test_p256(void) {
    uint8_t pub[64];
    uint8_t hash[32];
    uint8_t sig[96];
    unhex("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
          "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
          pub);

    // "sample"
    unhex("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf", hash);
    size_t n = unhex("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                     "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                     sig);
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 1);

    // Rejections, each a one-bit or one-byte mutation of the vector above.
    hash[0] ^= 0x01;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 0); // flipped hash bit
    hash[0] ^= 0x01;
    sig[6] ^= 0x01;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 0); // flipped r byte
    sig[6] ^= 0x01;
    pub[1] ^= 0x01;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 0); // pub off the curve
    pub[1] ^= 0x01;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n - 1) == 0); // truncated DER
    sig[n] = 0x00;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n + 1) == 0); // trailing garbage

    // Out-of-range scalars: r or s of 0 or n, s kept from the "sample"
    // vector where a live one is needed.
    uint8_t bad[96];
    size_t bad_len = unhex("3026020100"
                           "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                           bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bad_len) == 0); // r = 0
    bad_len = unhex("3026022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                    "020100",
                    bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bad_len) == 0); // s = 0
    bad_len = unhex("3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
                    "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                    bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bad_len) == 0); // r = n
    bad_len = unhex("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                    "022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                    bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bad_len) == 0); // s = n

    // "test"
    unhex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", hash);
    n = unhex("3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
              "0220019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
              sig);
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 1);

    // "chapulin"
    unhex("233f842649c70a89c3c76f0f6cbc3ce8a2e7e853f3a179f9993098098e1451ab", hash);
    n = unhex("30440220515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f"
              "022077ef4265782218e9cdc7fe27f236602794bb2c1a32285ced516bd5d77042d4d0",
              sig);
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 1);
}

#endif
