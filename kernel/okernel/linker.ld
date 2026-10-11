/* Layout do okernel na metade alta (SDD v1.0, seção 6). Um PT_LOAD por
   permissão, cada um começando em página própria, para o optboot (T-101) e
   as tabelas de página (T-103, T-107) aplicarem W^X sem dividir páginas. */

ENTRY(kernel_entry)

KERNEL_BASE = 0xffffffff80000000;

PHDRS
{
    text   PT_LOAD FLAGS(5); /* R-X */
    rodata PT_LOAD FLAGS(4); /* R-- */
    data   PT_LOAD FLAGS(6); /* RW- */
}

SECTIONS
{
    . = KERNEL_BASE;

    .text : ALIGN(4K) { *(.text .text.*) } :text

    . = ALIGN(4K);
    .rodata : { *(.rodata .rodata.*) } :rodata

    . = ALIGN(4K);
    .data : { *(.data .data.*) } :data
    .bss : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) }
}
