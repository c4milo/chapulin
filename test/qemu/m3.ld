/* MPS2-AN385: 4 MB of ZBT SRAM at address zero holds everything; the
   stack grows down from the top. */
MEMORY { SRAM (rwx) : ORIGIN = 0x00000000, LENGTH = 4M }
SECTIONS {
  .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) } > SRAM
  .data : { *(.data*) } > SRAM
  .bss : {
    __bss_start = .;
    *(.bss*) *(COMMON)
    __bss_end = .;
  } > SRAM
  __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
