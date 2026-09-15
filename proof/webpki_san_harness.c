// Proves: webpki_match_san's walk over a GeneralNames, in two parts,
// split the way pem_step and pem split the PEM decoder.
//
// read_entry, the static that reads one GeneralName — its tag, checked
// against the nine GeneralName tags, its length, its content, the
// dNSName compare — is proven from ANY reader state over a GeneralNames
// content of up to CH_WEBPKI_EXT_TLV_MAX bytes, the real bound: any
// position, any length, either err value, against any host of up to
// CH_PROOF_HOST_LEN bytes. read_entry returns 1 only for an entry
// whose first byte is_general_name_tag accepts. The loop's termination
// depends on the rest of the contract: a well-formed entry leaves err
// clear and moves the position forward by at least two bytes and never
// past the end, so the loop ends within half the content length; and
// *matched is 0 or 1 whatever it was before. Induction over the entries
// extends that to a GeneralNames of any length, not only the ones the
// bound below admits.
//
// webpki_match_san itself — the SEQUENCE header, its length check, the
// loop over read_entry — is proven over any bytes of up to
// CH_PROOF_SAN_LEN, the bound at which the unrolled loop converges;
// the launch line records it. The host is short in both parts on
// purpose. The walk passes host and host_len to match_dns_name without
// change and reads no byte of host itself, and webpki_name proves that
// compare with the host at its real 253-byte bound and the presented
// name at CH_WEBPKI_EXT_TLV_MAX. With the host at 253 bytes here, a
// 64-byte GeneralNames wrote a 7.9 GB CNF and returned no verdict,
// because every unrolled entry repeats the whole compare.
//
// CONCRETE: real bodies, the real rbuf (buf.c) and the real DER
// readers (x509_der.c) on the command line, the file's full dependency
// closure.
#include "harness.h"

#include "webpki_name.c"

#ifndef CH_PROOF_SAN_LEN
#define CH_PROOF_SAN_LEN 64
#endif
#ifndef CH_PROOF_HOST_LEN
#define CH_PROOF_HOST_LEN 16
#endif

int main(void) {
    uint8_t host[CH_PROOF_HOST_LEN];
    fill_nondet(host, sizeof host);
    size_t host_len = nondet_size_t();
    __CPROVER_assume(host_len <= sizeof host);

    // One entry from any reader state at the real GeneralNames bound.
    uint8_t content[CH_WEBPKI_EXT_TLV_MAX];
    fill_nondet(content, sizeof content);
    size_t content_len = nondet_size_t();
    __CPROVER_assume(content_len <= sizeof content);
    rbuf r;
    rb_init(&r, content, content_len);
    r.off = nondet_size_t();
    __CPROVER_assume(r.off <= content_len);
    r.err = nondet_u8() & 1;
    size_t before = r.off;
    int matched = nondet_u8() & 1;
    if (read_entry(&r, host, host_len, &matched)) {
        __CPROVER_assert(is_general_name_tag(content[before]),
                         "a well-formed entry starts with a GeneralName tag");
        __CPROVER_assert(!r.err, "a well-formed entry leaves err clear");
        __CPROVER_assert(r.off >= before + 2,
                         "a well-formed entry moves the position by two or more");
        __CPROVER_assert(r.off <= r.len,
                         "a well-formed entry never moves the position past the end");
    }
    __CPROVER_assert(matched == 0 || matched == 1, "matched stays 0 or 1");

    // The walk over any GeneralNames bytes against a fresh host.
    uint8_t san[CH_PROOF_SAN_LEN];
    fill_nondet(san, sizeof san);
    size_t san_len = nondet_size_t();
    __CPROVER_assume(san_len <= sizeof san);
    fill_nondet(host, sizeof host);
    host_len = nondet_size_t();
    __CPROVER_assume(host_len <= sizeof host);
    int walked = webpki_match_san(san, san_len, host, host_len);
    __CPROVER_assert(walked == 0 || walked == 1, "match_san answers 0 or 1");
    return 0;
}
