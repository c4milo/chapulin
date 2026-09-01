// M-profile entry shim for newlib/rdimon images on QEMU's MPS2-AN385:
// the CPU boots from the vector table at address zero, and newlib's
// crt0 only knows _start. SP comes from the table; crt0 then asks the
// semihosting host for the heap and stack bounds (SYS_HEAPINFO), so
// nothing else is set up here.
extern unsigned char __stack_top[];
extern void _start(void);

__attribute__((section(".vectors"), used)) static const struct {
    unsigned char *sp;
    void (*reset)(void);
    void (*rest[14])(void);
} vectors = {__stack_top, _start, {0}};
