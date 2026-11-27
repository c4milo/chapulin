# Performance pitfalls

Each entry is a performance trap this tree has paid for: what was seen, why it happened and the
rule it left. [docs/performance.md](performance.md) states the method these rules serve, and
[docs/decisions.md](decisions.md) records the decisions the entries cite.

1. **Symptom.** The 16-byte wipe after each AES block took 7.5 µs of a 16 KiB AES-GCM record, more
   than the AES rounds (044a49c).

   **Cause.** `ct_wipe` stores one byte per iteration through a volatile pointer and is a call, and
   `aes_hw.c` ran it after every block.

   **Rule.** Wipe a buffer once, after the loop that fills it, never once per block.

2. **Symptom.** gcc 13's AES-GCM counter mode took 16.5 µs of a 16 KiB record where clang's took
   1.8.

   **Cause.** gcc at `-O2` leaves a loop of eight iterations over vector states rolled and keeps
   the states in memory, so every round loads and stores all eight.

   **Rule.** A loop over the states a pass keeps in registers carries `#pragma GCC unroll`, and
   every change is measured under gcc as well as clang.

3. **Symptom.** clang's GHASH took 2.6 and 2.8 µs of a 16 KiB record where gcc's took 2.2, on the
   same core.

   **Cause.** clang loads each lane of a vector that PMULL reads from memory as a 64-bit word in a
   general register and moves it back into a vector register, two moves for each operand.

   **Rule.** Read a PMULL loop's disassembly under both compilers, and look for `fmov` and `dup`
   from general registers inside it.

4. **Symptom.** The vector Poly1305 took 4.7 µs of a 16 KiB record in one bench build under the
   VM's clang 18, and 3.0 µs in a build whose only difference was a function in `aes_hw.c`.

   **Cause.** Where the linker places the function: the first build with `-falign-functions=64`
   took 2.8 µs.

   **Rule.** When a row moves on a path the change did not touch, rebuild with functions aligned
   before reading the move as the change's.

5. **Symptom.** `bin/ghash_equiv_test` found powers of H in the stack below a GHASH call after the
   call had wiped the state that held them (88c64be).

   **Cause.** Holding the eight powers in registers across a pass, clang and gcc copied some to
   stack slots of their own, which the wipe of the state does not clear.

   **Rule.** Read a value the wipe must clear from the wiped state, through a volatile lvalue, each
   time it is used, and run the stack check after every change to a loop that holds one.

6. **Symptom.** gcc 13's one-pass seal loop took 3.6 µs of a 16 KiB record where it had taken 2.7,
   once the open called the same exclusive-or.

   **Cause.** gcc at `-O2` kept one out-of-line copy of a helper that two pass loops call. For the
   AES rounds, whose keys are bytes and so may alias the states, such a copy stored all eight
   states every round.

   **Rule.** A helper that works on the states a pass keeps in registers is `static inline`, and a
   pass loop's disassembly under gcc holds no call.

7. **Symptom.** gcc 13's one-pass open loop took 3.5 µs of a 16 KiB record where its seal loop took
   2.6.

   **Cause.** With the first pass's hash before the loop, gcc counted the low byte of each counter
   in a register of its own and built each counter word with `bfi`, where the seal's loop reverses
   one word with `rev`.

   **Rule.** Count `bfi` and `rev` in a pass loop's counter code under gcc, and when gcc builds the
   counters from bytes, change the loop's shape rather than the arithmetic.

8. **Symptom.** Under clang 18, `bin/ghash_equiv_test` found powers of H in the stack below the
   one-pass open, and it passed under Apple clang and gcc.

   **Cause.** With a pass's hash and its AES rounds in one block, clang 18 moved the powers'
   volatile reads up among the rounds and ran out of registers.

   **Rule.** Put a pass loop's hash and its rounds in separate `if` blocks, and run the stack check
   under clang 18 as well as the compilers `make check` runs.

9. **Symptom.** On the EPYC 7763 under gcc 13, the server side of a pinned RSA-2048 handshake took
   2.07 ms where it had taken 1.88, after a change to `sha3.c`, which that handshake never calls.
   The signature's own row, in another program, stayed at 1.74 ms.

   **Cause.** RSA on 64-bit words runs at one of two speeds on that CPU, by where the linker places
   it. With `-falign-functions=64` the signature's row took 1.93 ms and the RSA-2048 verify's 65.8
   µs against 59.0, and the handshake's stayed at 2.07 ms.

   **Rule.** A build with functions aligned does not cure this one: it shows the slower speed. Read
   a move of about a tenth on a path the change did not touch against that build's figure, and when
   they agree, record it as placement and leave the change alone.

10. **Symptom.** An eight-block ChaCha20 pass took 36.6 µs over 16 KiB under gcc 13 and 8.4 under
    clang 18, in a scratch timing loop.

    **Cause.** gcc 13 at `-O2` kept one out-of-line copy of a `static inline` function that ran a
    quarter round on both groups of a pass, called eight times a double round, so every call stored
    the 32 state vectors to memory and loaded them back.

    **Rule.** Build a pass's rounds from a helper small enough that gcc inlines it, such as one
    quarter round on one group, and read the round loop's disassembly under gcc for a call.

11. **Symptom.** On the CPU clock, an AES-GCM seal through OpenSSL took 5.9 µs for some minutes on
    the M1 Pro, and 2.1 µs before and after.

    **Cause.** macOS placed the process on efficiency cores while other work held the performance
    cores, and a CPU clock counts that time as it counts any other. Under `taskpolicy -b`, which
    runs a process on those cores, the same seal took 7.2 µs.

    **Rule.** Read a row's spread between runs before its median. A run on efficiency cores moves
    the spread past 100%, and `bench/primitives.sh` warns past 50%.

12. **Symptom.** The AES-GCM AEAD read as 1.05 times OpenSSL's seal on macOS, and under a key
    expanded for the record, which is the operation OpenSSL timed, as 1.13 times.

    **Cause.** OpenSSL 3.6's `speed -aead` sets the key for every operation, where 3.0's sets it
    before the loop, and for ChaCha20-Poly1305 3.6 runs one update with no nonce and no tag.

    **Rule.** Before a ratio against another library's benchmark, read what one of its operations
    holds in the release that ran, and time a 16-byte operation to confirm it. `bench/record.sh`
    names each OpenSSL row after the stage that times the same operation.

13. **Symptom.** gcc 13 for arm64 wrote 13 vector registers to the stack in `sha3_hw.c`'s
    permutation, and three a round with four lanes held in a struct the function wiped, where clang
    18, 21 and 23 wrote none.

    **Cause.** A round of Keccak-f[1600] keeps 32 values at once, the 25 lanes and seven more, and
    arm64 has 32 vector registers. A compiler that needs a 33rd writes a lane to a slot it picks,
    and no wipe written in C clears one.

    **Rule.** Before a path that keeps every register live holds secrets, count its stores of vector
    registers to the stack under each compiler that builds it. Decision 99 builds this one under
    clang alone.

14. **Symptom.** Apple clang 21 and clang 23 compiled a second copy of an earlier form of
    `sha3_hw.c`'s permutation for the arguments one caller passed, and the second copy wrote five or
    six lanes to the stack where the first wrote none.

    **Cause.** A compiler picks the registers of each copy of a function anew.

    **Rule.** Call a function whose register use a check depends on through a volatile function
    pointer, so the one copy compiled is the copy checked (decision 99).

15. **Symptom.** With four lanes of the Keccak state kept in memory to free four registers, clang
    took 30% longer over 16 KiB, and 2.5% longer once the round computed their row first.

    **Cause.** The next round's column parities read those lanes first, so each read waited for the
    store the round before had just made.

    **Rule.** A value a loop keeps in memory to free a register is written early in an iteration and
    read late.

16. **Symptom.** Under gcc 13 on x86-64, an ML-KEM-768 encapsulation spent 49,591 of its 515,432
    instructions in `sha3.c`'s `block_bytes`, which writes out squeezed bytes.

    **Cause.** gcc at `-O2` kept `lane_to_bytes`, a loop over a lane's eight bytes, as a loop: a
    shift and a one-byte store each iteration. With each byte named, it compiles the eight stores to
    one 8-byte store.

    **Rule.** Name each byte of a lane's store, as `lane_from_bytes` names each byte of its load,
    and count a byte loop's stores in gcc's disassembly.

17. **Symptom.** The Jacobian key exchange's multiplication took 58.2 µs on the M1 Pro where a
    scratch program's, on the same products and sums, took 54.0 (decision 112).

    **Cause.** The doubling computed Z3 = 2 Y1 Z1 last, as the Explicit-Formulas Database writes it,
    and the next doubling squares Z first, so each of 253 doublings waited for the product and the
    sum that ended the one before. Every field operation is a call, and the core starts a call's
    work before the call before it ends only where it reads nothing that call writes.

    **Rule.** In a chain of point formulas, compute first what the next formula reads first, and
    time the chain, never one formula alone.

18. **Symptom.** On the EPYC 7763 under gcc 13 the 64-byte SHA-384 row read 500 ns where the call
    took 408, and under clang 113 ns over its call (run 38140976845).

    **Cause.** `bench_consume` added every byte of the digest into a volatile after each call: a
    load, an add and a store for each byte. The hash, MAC and tag rows consumed their whole output,
    the public-key rows one byte, and `openssl speed` has no such loop.

    **Rule.** A row's sink consumes one byte of the output. Before a short row is set beside another
    library's, time the call with the bench's own loop and without it.

19. **Symptom.** Under clang 23, `rec_seal` of a 16 KiB ChaCha20-Poly1305 record under `ch_cfg.cpu`
    0x1f read 14.42 µs on one EPYC 7763 runner and 9.36 µs on another, with 0.1% between the five
    runs of each, while `aead_seal` read 9.11 µs on both (runs 38097442274 and 38100535828).

    **Cause.** clang did not align the frame of `chacha20_avx2.c`'s `pass` to 32 bytes, and the
    round loop stores and reloads six state words in 32-byte stack slots. Linux places each
    process's stack at a random address, in steps of 16 bytes. At 6 of the 256 positions within a
    page one of those slots lay across the page boundary, and the exclusive-or of 16 KiB took 1.25
    to 1.84 times as long. At every other position 16 past a multiple of 32, three of the slots lay
    across a cache line, and it took 1.04 times as long. Each row calls the kernel at its own stack
    depth, so one row of one process read slow, and that process's five runs agreed. Over 100
    processes on five runners, 30 read at least one of the bench's six rows on that kernel more than
    5% over its median. gcc 13 aligns the frame. `keccak_avx2.c`'s permutation had the same frame
    under clang: a call took 441 ns aligned, 675 ns at 16 past a multiple of 32, and up to 1,228 ns
    (runs 38153456033 and 38154870948). Both functions now carry the attribute that aligns the frame
    (decision 124): the exclusive-or takes 6,231 to 6,350 ns and the permutation 440 to 442 ns at
    every one of 273 stack positions, and over 80 processes on two runners none read one of the six
    rows more than 3% over its median (run 38159239411).

    **Rule.** A bench process has one stack address, and the spread between its runs does not see
    it. When `bench/record.sh` warns that a record row differs from the sum of its parts, or a row
    moves on one runner alone, time the binary in several new processes, or under `setarch -R` at
    several sizes of the environment, before reading the move. Under clang, read the prologue of a
    function that keeps 256-bit values in stack slots inside a loop for `and rsp`, as `make
    lint-frame-align` does for those two files and for `sha512_avx2.c` (INV-49).

20. **Symptom.** `rec_seal_without_aead` read the copy of a 16 KiB plaintext as 257 ns in one record
    on the EPYC 7763 and as 684 ns in another, and in a scratch program whose plaintext and record
    buffers started at the same offset within a page the copy took 5.4 µs.

    **Cause.** glibc 2.39 on that CPU copies more than 2,112 bytes with `rep movsb`. With the
    destination 1 to 31 bytes past the source's offset within a page, 16 KiB takes 5.3 to 5.6 µs in
    every process, against about 0.25 µs at the other offsets: a record's body starts 5 bytes past
    the record, so a plaintext and a record at the same offset are in that range. With the bench's
    buffers, 61 bytes apart, the copy takes 0.25 µs unless a source page and the destination page
    its bytes go to have physical frame numbers equal modulo 16. It then takes 0.44 to 1.3 µs: in
    243 of 900 processes on three runners, each of which had such a pair, and in none of the 657
    that had none. Under `GLIBC_TUNABLES=glibc.cpu.x86_rep_movsb_threshold=16777216`, which keeps
    glibc off `rep movsb`, the copy takes at most 0.37 µs at any offset, and 0.16 to 0.18 µs in each
    of 300 processes with the bench's buffers. An EPYC 9V45 showed neither effect (run 38154870948).
    `bench_state` now starts its plaintext on a page boundary and its record buffer 2,048 bytes into
    a page, so the copy's destination is 2,053 bytes past its source's offset, and the copy took 250
    ns in each of 600 processes on two runners (run 38159239411).

    **Rule.** Keep a timed copy's destination more than 31 bytes from its source's offset within a
    page, and read `rec_seal_without_aead` beside `rec_seal` before reading a move of up to 1 µs in
    a 16 KiB row as the AEAD's.

21. **Symptom.** On the EPYC 7763 under clang 23, `sha384_of_cpu` of 64 bytes under `CH_CPU_AVX2`
    read 230 ns in a program linked with `sha512_avx2.c` after decision 128's quarter steps and 205
    ns in one linked with the file before them, on each of 11 runners, while the kernel alone over
    one block read 182 ns and 186 (run 38182747184).

    **Cause.** That call runs at one of two speeds on that CPU by where the kernel's code starts
    within a 64-byte line. Linked with 0, 16, 32 and 48 bytes of padding before the kernel's object,
    the kernel after the change read 230, 230, 203 and 232 ns and the one before it 205, 234, 235
    and 235, on each of 13 runners. The 16 KiB row and the kernel alone over one block did not move
    with the padding, and under gcc 13 one padding of the four read 230 ns where the other three
    read 220 to 224 (run 38184809651). What in the CPU makes the two speeds was not found.

    **Rule.** A bench program links a kernel at one address. Before a move of a tenth in a row of
    one block is read as a change's, link the kernel at each of the four offsets a function takes
    within a 64-byte line and read the row at all four.

22. **Symptom.** Under `qemu-x86_64` 8.2.2, `sha512_avx2_compress_blocks` as gcc 13.3 compiles it
    took SIGSEGV on one block that ends at the last mapped byte before an unmapped page, and passed
    as clang 18 compiles it.

    **Cause.** gcc loads each four words of a block as a 16-byte VMOVDQU and a VINSERTI128 whose
    second operand is 16 bytes of memory, and that qemu reads past those 16 bytes: the same
    VINSERTI128 on the last 16 mapped bytes took the signal in a probe of its own, where a 16-byte
    VMOVDQU of them did not, and a CPU reads 16. clang loads a block in four 32-byte VMOVDQU.

    **Rule.** Read a fault under qemu-user at an instruction with a memory operand against that
    operand's size before reading it as the code's. A gcc host object that runs under that qemu with
    `CH_CPU_AVX2` needs 16 mapped bytes after a message, and what a kernel reads past its input is
    measured on a CPU.

23. **Symptom.** gcc 13's AVX2 ChaCha20 pass stored and loaded 12 of its 16 state words in each
    double round, 31 stack references where clang wrote 14, and its keystream took 6.27 µs over 16
    KiB where it takes 5.56 (decision 210).

    **Cause.** The lane type was `__m256i`, four 64-bit lanes, and an add or a shuffle of another
    lane width converts its result. gcc keeps the value before the conversion and the value after it
    in a pseudo-register each. At a loop's back edge both are live when the next pass reads one and
    the code after the loop reads the other.

    **Rule.** Give a loop's vector state the type its operations write, such as a GNU C vector of
    `uint32_t` with the C operators, and count the loop's stack references in gcc's disassembly.

24. **Symptom.** On x86-64 one round of Keccak-f[1600], in place on one array, was 272 instructions
    under gcc 13.3 and 230 under clang 23, and 135 of them compute. With a second array that the
    round writes, gcc's round was 247, and clang 18 loaded two lanes with one 16-byte load. Once the
    round was 210 and 199 instructions, gcc's time on the EPYC 7763 was 0.89 of its time before and
    clang's 0.99.

    **Cause.** A round holds 25 lanes and theta's ten values, and x86-64 has 15 general registers.
    Each compiler chose the values it kept in stack slots, and wrote a load, a store or a move for
    each choice. With two arrays, gcc kept each lane it stored as a value for the next round and
    stored it once more in a stack slot. clang's 16-byte load read two lanes that the round before
    stored 8 bytes at a time, and such a load waits for both stores. And a round's first loads, for
    theta's parities, read the lanes that the round before stored: a form that hands the parities to
    the next round as values took 0.945 of the time under clang with 14 more instructions (decision
    217).

    **Rule.** Where a loop holds more values than registers, keep them in memory at places the text
    names, in a function that is out of line, and put an empty statement that clobbers memory where
    each load must be a load (decision 216). Count the loop's loads, stores and moves under each
    compiler, and write a row's lines in the order that lets each two-operand instruction write over
    a value read for the last time. Then time the form on the judge: a count that falls is not a
    time that falls.

25. **Symptom.** On macOS for x86-64, the function of 24 Keccak rounds wrote theta's value d2 to a
    slot below the stack pointer, where each Linux build measured wrote no value of the state to a
    slot.

    **Cause.** macOS keeps rbp as the frame pointer, so a function has 14 general registers where a
    Linux build has 15. A row of the round held 13 values, and the loop held two more: a count and
    the table's address. clang for Linux wrote the same slot with `-fno-omit-frame-pointer`.

    **Rule.** Count a loop's live values against 14 registers, not 15. Keep a loop's control in one
    register: a pointer into the table, with the end's address computed at the test (decision 218).
    Search the stack of a build with the frame pointer, as `check-rosetta` and the qemu lane's
    `sha3-stack` part do.

26. **Symptom.** gcc 15 for arm64 and x86-64 stored 32 coefficients of ML-KEM's noise in
    `mlk_vector_noise`'s own frame on each step, and clang stored none (decision 225).

    **Cause.** `lanes_noise` filled an array of four vectors that its caller then stored. With the
    array's address taken, gcc kept the array in memory, and nothing wiped it.

    **Rule.** A lane function that computes secret vectors stores them into their destination
    itself, and takes no array of vectors as its output. Read gcc's code of each secret lane path
    for stores to the stack.

27. **Symptom.** On the Xeon Platinum 8573C the two-pass ChaCha20-Poly1305 seal of a 16 KiB record
    read 1.03 to 1.09 times OpenSSL's time and varied 11 to 18% between runs, while its keystream
    and its Poly1305 alone added up to 0.93 of it.

    **Cause.** After 3 ms of work with no 512-bit instruction, the two-pass seal ran its AVX-512
    keystream at the AVX2 kernel's speed for its next 10 to 20 calls. The kernels alone, and a seal
    in one pass, ran at full speed from their second call. `bench/record.sh` times the seal's
    batches after rows that copy records.

    **Rule.** Time a kernel after scalar work as well as in a loop of itself, and read a whole row
    against the sum of its parts in the same run (decision 226).

28. **Symptom.** On CPUs with AVX-512 IFMA, the stack below the AVX-512 ChaCha20-Poly1305 seal and
    open held the key's 32 bytes in order: under gcc 15 below both (`check.yml` run 43361141856),
    and under gcc 13 and clang 23 below the open (decision 228).

    **Cause.** Two causes. `rows_keystream` built a row pass's four input rows in an array, and gcc
    15 kept the array in the pass's frame: rows 1 and 2 hold the key's words, four to a quarter, so
    the two side by side spell the key. And `chacha20_avx512_xor` loaded the key as one 32-byte
    value to write the input words; where a function that reads the words was inlined, gcc 13 and
    clang 23 kept that value in a register for the reads and saved it in the entry's frame across
    the calls of `pass`. No check before the push ran the search: it needs AVX-512, which the M1,
    Rosetta and the qemu lane lack.

    **Rule.** Give a vector of key words to the statement that consumes it, and hold no array of
    such vectors. Keep every function that reads the key words out of line from the function that
    writes them. Before a push, run a test that needs instructions the M1 lacks on a runner that has
    them, under each compiler, or under SDE.

29. **Symptom.** On the EPYC 7763 the Keccak rounds that keep the state in memory took 41.5 to 45
    cycles each, and OpenSSL's took 42.6. Two independent states, a round of each in turn, took 0.96
    to 0.98 of one state's time a permutation (decision 231).

    **Cause.** Each load of a round reads a lane that the round before stored. On that CPU a loop
    that reads four words the pass before stored runs 2.4 ALU operations a cycle. At other addresses
    it runs 3.4. The round ran 3.0 of the 4.0 a long loop of its operations runs. The Xeon 8573C
    runs the same round at 4.0 of its 4.5, so there each operation removed is time saved.

    **Rule.** Measure a loop's ALU operations a cycle on each CPU of the scoreboard. Compare them
    with a long loop of the same operations. If the loop runs below that rate and reads words it
    just stored, count those loads. Time a form with fewer of them before a form with fewer
    operations.

30. **Symptom.** On the Xeon Platinum 8370C the ChaCha20-Poly1305 seal of 16 KiB read 1.09 times
    OpenSSL's time under gcc and 1.18 times under clang, and took 0.87 and 0.92 of OpenSSL's cycles
    (bench run 44230474748, lab run 44330567657).

    **Cause.** The IFMA Poly1305 lowered the core clock to 2.79 to 2.84 GHz, and the seal ran at
    2.89 to 3.38 GHz. The 512-bit keystream alone and OpenSSL's seal ran at 3.38 GHz.

    **Rule.** Read a row's core clock beside its time: a chain of dependent adds after the work
    gives it. Compare cycles to find the code's share of a gap (decision 238).

31. **Symptom.** Under clang 23 the AVX-512 one-pass seal took 5 to 8% more cycles than its
    keystream and its Poly1305 alone, and under gcc 13 it took 5 to 10% fewer.

    **Cause.** clang schedules before it allocates registers, and under its generic model it put a
    group's 36 IFMA products in one block, which waited on port 0 beside the rotations. gcc
    schedules after, and moved the products among the rotations.

    **Rule.** Read the order of each compiler's instructions, not the source's. Under clang, the
    tune of a target attribute names the model its scheduler reads (decision 238).
