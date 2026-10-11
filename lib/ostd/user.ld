/* Layout dos binários de usuário do Optimus (T-211), ligados com
   `-C relocation-model=static` pelo xtask: ET_EXEC na metade baixa, um
   PT_LOAD por permissão e cada um em página própria (W^X sem dividir
   páginas, como o oelf exige).

   `.ostd_entry` junta o `static OSTD_ENTRY` criado por `ostd::entry!`
   (o binário não pode usar `#[no_mangle]`, então o símbolo é achado pelo
   nome da seção de dados dele) e vem antes de `.rodata`, que senão o
   engoliria. */

ENTRY(_start)

USER_BASE = 0x200000;

PHDRS
{
    text   PT_LOAD FLAGS(5);    /* R-X */
    rodata PT_LOAD FLAGS(4);    /* R-- */
    data   PT_LOAD FLAGS(6);    /* RW- */
}

SECTIONS
{
    . = USER_BASE;

    .text : ALIGN(4K) { *(.text._start) *(.text .text.*) } :text

    . = ALIGN(4K);
    .ostd_entry : {
        __ostd_entry = .;
        KEEP(*(.rodata.*OSTD_ENTRY* .data.rel.ro.*OSTD_ENTRY*))
    } :rodata
    .rodata : { *(.rodata .rodata.*) } :rodata
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) } :rodata
    .got : { *(.got .got.*) } :rodata

    . = ALIGN(4K);
    .data : { *(.data .data.*) } :data
    .bss : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment*) *(.dynamic) *(.interp) }
}

ASSERT(SIZEOF(.ostd_entry) == 8, "use ostd::entry!(main) exatamente uma vez no binário");
