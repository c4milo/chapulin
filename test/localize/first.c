// The first source of the object test/localize-check.sh partially links
// and localizes. It holds a global of each kind tools/localize_symbols.zig
// treats: a kept function, a function the other source calls, a weak
// definition, a hidden one, global data the other source reads, and a
// call to a hook no source defines, which stays undefined.
extern int ext_hook(int x);

int first_table[4] = {1, 2, 3, 4};

static int helper(int x) {
    return (x * 3) + first_table[x & 3];
}

int first_internal(int x) {
    return helper(x) + 1;
}

__attribute__((weak)) int first_weak(int x) {
    return x - 1;
}

__attribute__((visibility("hidden"))) int first_hidden(int x) {
    return x ^ 5;
}

int first_public(int x) {
    return first_internal(x) + ext_hook(x);
}
