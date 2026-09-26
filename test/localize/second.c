// The second source of the object test/localize-check.sh localizes. It
// calls the first source's globals through a table of pointers, so the
// object holds data relocations against symbols that become local, beside
// the code relocations of the direct calls.
extern int first_table[4];
int first_internal(int x);
int first_weak(int x);
int first_hidden(int x);

const int second_data = 7;

int (*const second_calls[3])(int) = {first_internal, first_weak, first_hidden};

int second_public(int x) {
    return second_calls[x % 3](x) + first_internal(x) + first_table[1] + second_data;
}
