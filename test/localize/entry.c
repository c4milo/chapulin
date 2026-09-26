// The entry point test/localize-check.sh links against the localized
// object of a target it cannot run: no libc and no startup files, so a
// cross target needs nothing but the linker. The link resolves every
// relocation against the rewritten symbol table, which is the check.
//
// Compiled with -DLOCALIZE_CALL_LOCAL it calls a function the object
// defines and made local, and then the link must fail.
int first_public(int x);
int second_public(int x);
int first_internal(int x);

volatile int localize_sink;

int ext_hook(int x) {
    return x;
}

void _start(void) {
#ifdef LOCALIZE_CALL_LOCAL
    localize_sink = first_internal(1);
#else
    localize_sink = first_public(1) + second_public(2);
#endif
    for (;;) {}
}
