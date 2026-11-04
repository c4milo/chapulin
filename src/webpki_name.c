// Hostnames for the web PKI trust mode (TRUST=webpki): the shape check
// on the caller's reference name, and the match of that name against
// the dNSName entries of a leaf's subjectAltName. Contract in webpki.h;
// the rules in docs/webpki.md ("Hostnames"). Every byte here is public —
// the caller's hostname, or a certificate's names — so variable time is
// fine and deliberate.
#include "webpki.h"

#include "buf.h"
#include "x509.h"

// RFC 1035 §2.3.4: a label is at most 63 bytes.
#define LABEL_MAX 63

// GeneralNames ::= SEQUENCE OF GeneralName.
#define TAG_SEQUENCE 0x30

// The nine arms of GeneralName ::= CHOICE (RFC 5280 §4.2.1.6), tagged
// IMPLICIT. DER gives each arm one identifier byte: context-specific
// class, the arm number, and the constructed bit exactly when the
// arm's type is constructed (X.690 §8.14). directoryName's Name is a
// CHOICE, which is always tagged explicitly, so that arm is
// constructed too.
#define TAG_OTHER_NAME 0xa0                  // [0] OtherName, a SEQUENCE
#define TAG_RFC822_NAME 0x81                 // [1] IA5String
#define TAG_DNS_NAME 0x82                    // [2] IA5String
#define TAG_X400_ADDRESS 0xa3                // [3] ORAddress, a SEQUENCE
#define TAG_DIRECTORY_NAME 0xa4              // [4] Name
#define TAG_EDI_PARTY_NAME 0xa5              // [5] EDIPartyName, a SEQUENCE
#define TAG_UNIFORM_RESOURCE_IDENTIFIER 0x86 // [6] IA5String
#define TAG_IP_ADDRESS 0x87                  // [7] OCTET STRING
#define TAG_REGISTERED_ID 0x88               // [8] OBJECT IDENTIFIER

static int is_letter(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int is_digit(uint8_t c) {
    return c >= '0' && c <= '9';
}

// The alphabet [A-Za-z0-9.-]; what it leaves out is the point. NUL
// and '*' are outside it, and every match below compares equal-length
// byte ranges against a name that passed this, so neither can match.
static int is_hostname_byte(uint8_t c) {
    return is_letter(c) || is_digit(c) || c == '.' || c == '-';
}

// Every label 1..LABEL_MAX bytes. The 1 refuses an empty label, and so
// a leading dot, a trailing dot and two dots in a row.
static int labels_ok(const uint8_t *host, size_t host_len) {
    size_t run = 0;
    for (size_t i = 0; i < host_len; i++) {
        if (host[i] != '.') {
            run++;
            continue;
        }
        if (run < 1 || run > LABEL_MAX) {
            return 0;
        }
        run = 0;
    }
    return run >= 1 && run <= LABEL_MAX;
}

// No label starts or ends with '-' (RFC 1123 §2.1, RFC 952). A byte
// is a label's first when it is the name's first or follows a dot, and
// a label's last when it is the name's last or precedes a dot.
static int label_edges_ok(const uint8_t *host, size_t host_len) {
    for (size_t i = 0; i < host_len; i++) {
        if (host[i] != '-') {
            continue;
        }
        if (i == 0 || i == host_len - 1 || host[i - 1] == '.' || host[i + 1] == '.') {
            return 0;
        }
    }
    return 1;
}

// The last label is the bytes after the last dot. RFC 6066 §3 forbids
// an IPv4 literal in server_name, and its last label is all digits.
static int last_label_all_digits(const uint8_t *host, size_t host_len) {
    size_t i = host_len;
    while (i > 0 && host[i - 1] != '.') {
        if (!is_digit(host[i - 1])) {
            return 0;
        }
        i--;
    }
    return 1;
}

int webpki_hostname_ok(const uint8_t *host, size_t host_len) {
    if (host_len < 1 || host_len > CH_HOSTNAME_MAX) {
        return 0;
    }
    for (size_t i = 0; i < host_len; i++) {
        if (!is_hostname_byte(host[i])) {
            return 0;
        }
    }
    return labels_ok(host, host_len) && label_edges_ok(host, host_len) &&
           !last_label_all_digits(host, host_len);
}

static uint8_t ascii_lower(uint8_t c) {
    if (c >= 'A' && c <= 'Z') {
        return (uint8_t)(c + ('a' - 'A'));
    }
    return c;
}

// Equal-length compare, ASCII case folded on both sides (RFC 6125
// §6.4.1 compares names case-insensitively).
static int names_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (ascii_lower(a[i]) != ascii_lower(b[i])) {
            return 0;
        }
    }
    return 1;
}

// The bytes before the first dot, or all of them when there is none.
static size_t first_label_len(const uint8_t *name, size_t name_len) {
    size_t n = 0;
    while (n < name_len && name[n] != '.') {
        n++;
    }
    return n;
}

// The presented name was "*." then suffix. The wildcard stands for
// exactly one label, the leftmost of host, so host is that label, a
// dot, then bytes equal to suffix. A suffix with no dot holds one
// label, and a wildcard directly under it — "*.com" — matches nothing
// (RFC 6125 §6.4.3). That dot is looked for in the host's bytes after
// the equal compare: the two are equal up to case and a dot folds to
// itself, so the answer is the same, and every loop here runs at most
// host_len times, which keeps the proof of the walk over a whole
// GeneralNames small (proof/webpki_san_harness.c).
static int match_wildcard(const uint8_t *suffix, size_t suffix_len, const uint8_t *host,
                          size_t host_len) {
    size_t first = first_label_len(host, host_len);
    if (first == host_len) {
        return 0;
    }
    const uint8_t *rest = host + first + 1;
    size_t rest_len = host_len - first - 1;
    if (rest_len != suffix_len || !names_equal(suffix, rest, suffix_len)) {
        return 0;
    }
    return first_label_len(rest, rest_len) != rest_len;
}

// One dNSName against host. A '*' anywhere but as the whole leftmost
// label is an ordinary byte here, and the exact compare then fails
// because host holds none: a partial-label wildcard matches nothing.
static int match_dns_name(const uint8_t *name, size_t name_len, const uint8_t *host,
                          size_t host_len) {
    if (name_len >= 2 && name[0] == '*' && name[1] == '.') {
        return match_wildcard(name + 2, name_len - 2, host, host_len);
    }
    return name_len == host_len && names_equal(name, host, host_len);
}

// Whether tag is one of the nine GeneralName identifier bytes above.
// Every other byte is refused: a universal tag such as OCTET STRING
// (0x04) or end-of-contents (0x00), a context-specific number above 8,
// an arm with the wrong constructed bit, and the first byte of the
// high-tag-number form (X.690 §8.1.2.4). That form sets the low five
// bits to 0x1f and continues the tag number in the next bytes, so a
// reader that took one tag byte would read a byte of the tag number
// as the length and frame every later entry at the wrong offset.
static int is_general_name_tag(uint8_t tag) {
    return tag == TAG_OTHER_NAME || tag == TAG_RFC822_NAME || tag == TAG_DNS_NAME ||
           tag == TAG_X400_ADDRESS || tag == TAG_DIRECTORY_NAME || tag == TAG_EDI_PARTY_NAME ||
           tag == TAG_UNIFORM_RESOURCE_IDENTIFIER || tag == TAG_IP_ADDRESS ||
           tag == TAG_REGISTERED_ID;
}

// One GeneralName at the reader's position: its CHOICE tag, which
// must be one of the nine, its length in X.690 §10.1's minimal form,
// its content. A dNSName's content is compared against host and a
// match sets *matched; the content of every other arm is skipped
// unread. Returns 1 on a well-formed entry, 0 on a malformed one. Its
// own function for the proof: one entry is proven from any reader
// state at the real GeneralNames bound, and the loop below at the
// bound where the whole walk converges (proof/webpki_san_harness.c),
// the same split as pem.c's per-character step.
static int read_entry(rbuf *r, const uint8_t *host, size_t host_len, int *matched) {
    uint8_t tag = rb_u8(r);
    if (!is_general_name_tag(tag)) {
        return 0;
    }
    size_t len = 0;
    if (!x509_read_len(r, &len)) {
        return 0;
    }
    const uint8_t *content = rb_bytes(r, len);
    if (content == NULL) {
        return 0;
    }
    if (tag == TAG_DNS_NAME && match_dns_name(content, len, host, host_len)) {
        *matched = 1;
    }
    return 1;
}

// GeneralNames ::= SEQUENCE OF GeneralName. The walk checks the tag
// and reads the length of every entry, and reads the content of
// dNSName entries only. A malformed entry anywhere is a refusal, even
// after a match.
int webpki_match_san(const uint8_t *san, size_t san_len, const uint8_t *host, size_t host_len) {
    rbuf r;
    rb_init(&r, san, san_len);
    size_t seq_len = 0;
    if (!x509_read_header(&r, TAG_SEQUENCE, &seq_len) || seq_len != rb_left(&r)) {
        return 0;
    }
    int matched = 0;
    while (rb_left(&r) > 0) {
        if (!read_entry(&r, host, host_len, &matched)) {
            return 0;
        }
    }
    return matched;
}
