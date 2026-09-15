// Proves: webpki_hostname_ok is memory-safe and UB-free over any host
// of up to CH_HOSTNAME_MAX bytes, its real bound, and honours the
// contract webpki_match_san depends on: a name it accepts is
// 1..CH_HOSTNAME_MAX bytes and holds no byte outside [A-Za-z0-9.-] — a
// nondet index stands for every position — so it holds neither NUL
// nor '*'. And match_dns_name, the static the walk calls once per
// dNSName entry, is safe in both its arms against any host of up to
// CH_HOSTNAME_MAX bytes and any presented name of up to
// CH_WEBPKI_EXT_TLV_MAX bytes. A dNSName's content lies inside one
// Extension TLV, and webpki.h's contract for webpki_read_extensions
// holds that TLV to CH_WEBPKI_EXT_TLV_MAX bytes, so no presented name
// the walk passes is longer. The leading "*." is chosen by nondet, so the
// wildcard arm is always in the formula. Spec.WebpkiName proves of the
// model what these asserts check of the C: an accepted host holds no
// NUL and no '*'.
//
// The walk over a GeneralNames has its own harness, webpki_san: one
// formula holding the walk and this compare at the real host bound
// wrote a 7.9 GB CNF at a 64-byte GeneralNames, because every entry
// of the walk unrolls the compare against the whole host.
//
// CONCRETE: real bodies, the real rbuf (buf.c) and the real DER
// readers (x509_der.c) on the command line, the file's full dependency
// closure.
#include "harness.h"

#include "webpki_name.c"

int main(void) {
    uint8_t host[CH_HOSTNAME_MAX];
    fill_nondet(host, sizeof host);
    size_t host_len = nondet_size_t();
    __CPROVER_assume(host_len <= sizeof host);
    if (webpki_hostname_ok(host, host_len)) {
        __CPROVER_assert(host_len >= 1 && host_len <= CH_HOSTNAME_MAX,
                         "an accepted host is 1..CH_HOSTNAME_MAX bytes");
        size_t i = nondet_size_t();
        __CPROVER_assume(i < host_len);
        __CPROVER_assert(is_hostname_byte(host[i]), "an accepted host holds only its alphabet");
        __CPROVER_assert(host[i] != 0 && host[i] != '*',
                         "an accepted host holds no NUL and no '*'");
    }

    // One presented name against a fresh host, either arm.
    uint8_t name[CH_WEBPKI_EXT_TLV_MAX];
    fill_nondet(name, sizeof name);
    size_t name_len = nondet_size_t();
    __CPROVER_assume(name_len <= sizeof name);
    if (nondet_u8() & 1) {
        name[0] = '*';
        name[1] = '.';
    }
    fill_nondet(host, sizeof host);
    host_len = nondet_size_t();
    __CPROVER_assume(host_len <= sizeof host);
    int matched = match_dns_name(name, name_len, host, host_len);
    __CPROVER_assert(matched == 0 || matched == 1, "match_dns_name answers 0 or 1");
    return 0;
}
