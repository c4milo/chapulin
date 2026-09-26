// The program test/localize-check.sh links against the localized object
// and runs, where the object is the host's own format. It defines the hook
// the object imports and checks what the two kept functions return, which
// the relocations against the localized symbols compute.
#include <stdio.h>

int first_public(int x);
int second_public(int x);

int ext_hook(int x) {
    return x * 10;
}

int main(void) {
    // first_public(2) = first_internal(2) + ext_hook(2) = (6 + 3 + 1) + 20.
    // second_public(4) calls second_calls[1], first_weak(4) = 3, then adds
    // first_internal(4) = 12 + 1 + 1, first_table[1] = 2 and second_data = 7.
    int got = first_public(2) + second_public(4);
    int want = 30 + (3 + 14 + 2 + 7);
    if (got != want) {
        (void)printf("localize-check: the program computed %d, not %d\n", got, want);
        return 1;
    }
    return 0;
}
