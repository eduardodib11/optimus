/* Layout do okernel na metade alta (SDD v1.0, seção 6). Um PT_LOAD por
   permissão, cada um começando em página própria, para o optboot (T-101) e
   as tabelas de página (T-103, T-107) aplicarem W^X sem dividir páginas.

   O kernel é PIE estático (T-103): ligado em KERNEL_BASE, e o optboot soma o
   deslocamento de KASLR aplicando as relocações R_X86_64_RELATIVE de
   .rela.dyn antes de mapear. Como as relocações são aplicadas na memória
   física, antes de qualquer mapeamento, os dados que só mudam por relocação
   (.data.rel.ro, .got) ficam no segmento R--. */

ENTRY(kernel_entry)

KERNEL_BASE = 0xffffffff80000000;

PHDRS
{
    text    PT_LOAD FLAGS(5);    /* R-X */
    rodata  PT_LOAD FLAGS(4);    /* R-- */
    data    PT_LOAD FLAGS(6);    /* RW- */
    dynamic PT_DYNAMIC FLAGS(4);
}

SECTIONS
{
    . = KERNEL_BASE;

    .text : ALIGN(4K) { __kernel_text_start = .; *(.text .text.*) } :text
    __kernel_text_end = .;

    . = ALIGN(4K);
    __kernel_rodata_start = .;
    .rodata : { *(.rodata .rodata.*) } :rodata
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) } :rodata
    .got : { *(.got .got.*) } :rodata
    .dynsym : { *(.dynsym) } :rodata
    .gnu.hash : { *(.gnu.hash) } :rodata
    .hash : { *(.hash) } :rodata
    .dynstr : { *(.dynstr) } :rodata
    .rela.dyn : { *(.rela.dyn .rela.*) } :rodata
    .dynamic : { *(.dynamic) } :rodata :dynamic
    __kernel_rodata_end = .;

    . = ALIGN(4K);
    .data : { *(.data .data.*) } :data
    .bss : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) *(.interp) }
}
