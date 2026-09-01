/* MPS2-AN385 for newlib+rdimon images: code in the ZBT SRAM at zero,
   data and bss above it, stack at the top of the same 4 MB. Keeps the
   init/fini arrays crt0 walks and the exidx tables gcc emits. */
MEMORY { SRAM (rwx) : ORIGIN = 0x00000000, LENGTH = 4M }
ENTRY(_start)
SECTIONS {
  .text : {
    KEEP(*(.vectors))
    *(.text*) *(.rodata*)
    . = ALIGN(4);
    __preinit_array_start = .; KEEP(*(.preinit_array)) __preinit_array_end = .;
    __init_array_start = .;    KEEP(*(.init_array*))   __init_array_end = .;
    __fini_array_start = .;    KEEP(*(.fini_array*))   __fini_array_end = .;
  } > SRAM
  .ARM.exidx : { __exidx_start = .; *(.ARM.exidx*) __exidx_end = .; } > SRAM
  .data : { *(.data*) } > SRAM
  .bss : { __bss_start__ = .; *(.bss*) *(COMMON) __bss_end__ = .; } > SRAM
  . = ALIGN(8);
  end = .; __end__ = .;
  __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
