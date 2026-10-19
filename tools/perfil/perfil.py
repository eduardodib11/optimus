# Perfil de uma volta de IPC ou de troca de contexto, instrução a
# instrução, pelo gdb ligado ao QEMU (T-331). O `cargo xtask perfil` roda
# este script com `gdb -batch -x`; ele não serve sozinho.
#
# Entrada (variáveis de ambiente):
#   PERFIL_KERNEL  ELF do kernel (release, com tabela de linhas)
#   PERFIL_SLIDE   deslocamento de KASLR (da serial)
#   PERFIL_PORT    porta do gdbstub do QEMU
#   PERFIL_NR      syscall que abre a volta (20 = ipc_call, 28 = yield)
#   PERFIL_SKIP    entradas dessa syscall a ignorar antes (aquecimento)
#   PERFIL_TITLE   título da seção do relatório
#   PERFIL_OUT     arquivo em que a seção é acrescentada
#   PERFIL_DUMP    (opcional) arquivo em que vai a volta inteira, uma
#                  instrução por linha, para estudar um trecho
#
# Para no `syscall_entry` com `rax` = PERFIL_NR, depois de PERFIL_SKIP
# entradas, e segue com `stepi` até a segunda volta ao anel 3: a primeira
# é a outra thread (servidor ou a outra do yield) e a segunda, a que
# chamou. O QEMU não entrega interrupções durante o passo a passo. Acrescenta
# a seção do relatório, em markdown, a PERFIL_OUT (a saída do gdb leva o
# eco de cada passo).

import collections
import os
import re

import gdb

KERNEL_HALF = 0xFFFF_8000_0000_0000
MAX_STEPS = 200_000

# Instruções com custo bem acima de um ciclo, ou que saem para o
# hipervisor sob KVM. A estimativa de ciclos de cada classe vale para um
# núcleo x86 recente sem mitigações de Spectre no convidado e serve só para
# ordenar as causas; a medida de verdade é o `cargo xtask bench` em KVM.
CLASSES = [
    ("syscall", r"^syscall\b", 70),
    ("sysret", r"^sysret", 70),
    ("iretq", r"^iretq", 150),
    ("swapgs", r"^swapgs", 10),
    ("mov cr3", r"^mov\s+%?cr3,|^mov\s+cr3,", 300),
    ("mov cr (outros)", r"^mov\s+%?cr[0248],|^mov\s+cr[0248],", 50),
    ("xsave/xsaveopt", r"^xsave", 100),
    ("xrstor", r"^xrstor", 100),
    ("fxsave/fxrstor", r"^fx(save|rstor)", 100),
    ("wrmsr", r"^wrmsr", 150),
    ("rdmsr", r"^rdmsr", 100),
    ("rdtsc/rdtscp", r"^rdtscp?\b", 25),
    ("lfence/mfence", r"^[lm]fence", 30),
    ("lock (RMW atômico)", r"^lock\b|^xchg\b.*\[|^xchg\b.*\(", 20),
    ("pushf/popf", r"^pushf|^popf", 20),
    ("cli/sti", r"^cli\b|^sti\b", 5),
    ("pause", r"^pause\b", 40),
]


def env(name):
    value = os.environ.get(name)
    if value is None:
        raise gdb.GdbError(f"perfil: falta {name}")
    return value


def pc():
    return int(gdb.parse_and_eval("$pc")) & 0xFFFF_FFFF_FFFF_FFFF


def short(name):
    """Nome de função Rust sem o hash e sem os genéricos."""
    if name is None:
        return "?"
    name = re.sub(r"::h[0-9a-f]{16}$", "", name)
    out, depth = [], 0
    for ch in name:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(depth - 1, 0)
        elif depth == 0:
            out.append(ch)
    name = "".join(out)
    return name.replace("{impl#", "{").replace("()", "") or "?"


def where(addr):
    """(função de verdade, função inline mais interna, arquivo:linha)."""
    try:
        block = gdb.block_for_pc(addr)
    except RuntimeError:
        block = None
    inner = outer = None
    while block is not None:
        if block.function is not None:
            name = block.function.print_name
            inner = inner or name
            outer = name
        block = block.superblock
    if outer is None:
        sym = gdb.execute(f"info symbol {addr:#x}", to_string=True)
        outer = inner = sym.split(" + ")[0].split(" in section")[0].strip()
    sal = gdb.find_pc_line(addr)
    if sal.symtab is not None:
        path = sal.symtab.filename
        for cut in ("/src/", "/library/"):
            if cut in path:
                path = path.split(cut, 1)[1]
                break
        loc, line = path, f"{path}:{sal.line}"
    else:
        loc = line = "?"
    return short(outer), short(inner), loc, line


def entry(addr):
    """Nome do símbolo, se `addr` é o começo dele (uma chamada)."""
    sym = gdb.execute(f"info symbol {addr:#x}", to_string=True)
    if " + " in sym or "No symbol" in sym:
        return None
    return short(sym.split(" in section")[0].strip())


def classify(asm):
    text = asm.strip()
    for name, pattern, _ in CLASSES:
        if re.search(pattern, text):
            return name
    return None


def table(rows, total, limit):
    lines = ["| | Instruções | % |", "|---|---:|---:|"]
    for name, n in rows[:limit]:
        lines.append(f"| `{name}` | {n} | {100 * n / total:.1f} |")
    rest = sum(n for _, n in rows[limit:])
    if rest:
        lines.append(f"| (outras {len(rows) - limit}) | {rest} | {100 * rest / total:.1f} |")
    return "\n".join(lines)


def main():
    kernel = env("PERFIL_KERNEL")
    slide = int(env("PERFIL_SLIDE"), 0)
    nr = int(env("PERFIL_NR"))
    skip = int(env("PERFIL_SKIP"))
    title = env("PERFIL_TITLE")
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set architecture i386:x86-64")
    gdb.execute(f"symbol-file -o {slide:#x} {kernel}", to_string=True)
    gdb.execute(f"target remote 127.0.0.1:{env('PERFIL_PORT')}", to_string=True)
    gdb.execute("set disassembly-flavor intel")
    # O parser de expressões do Rust não acha símbolos só do asm.
    gdb.execute("set language c")
    bp = gdb.Breakpoint("*syscall_entry", internal=True)
    bp.condition = f"$rax == {nr}"
    bp.ignore_count = skip
    gdb.execute("continue", to_string=True)
    bp.delete()

    trace = []
    phase = 0
    in_kernel = True
    for _ in range(MAX_STEPS):
        addr = pc()
        kernel_now = addr >= KERNEL_HALF
        if in_kernel and not kernel_now:
            phase += 1
            if phase == 2:
                break
        in_kernel = kernel_now
        trace.append((phase if kernel_now else -1, addr))
        gdb.execute("stepi", to_string=True)
    else:
        raise gdb.GdbError("perfil: a volta não terminou")

    arch = gdb.selected_frame().architecture()
    info = {}
    for _, addr in trace:
        if addr not in info:
            asm = arch.disassemble(addr)[0]["asm"]
            loc = where(addr) if addr >= KERNEL_HALF else ("(anel 3)", "(anel 3)", "user.S", "user.S")
            info[addr] = (classify(asm), loc, entry(addr) if addr >= KERNEL_HALF else None)

    dump = os.environ.get("PERFIL_DUMP")
    if dump:
        with open(dump, "a", encoding="utf-8") as f:
            f.write(f"# {title}\n")
            for p, a in trace:
                asm = arch.disassemble(a)[0]["asm"]
                f.write(f"{p}\t{a:#x}\t{info[a][1][0]}\t{info[a][1][1]}\t{info[a][1][3]}\t{asm}\n")

    total = len(trace)
    kernel_n = sum(1 for p, _ in trace if p >= 0)
    phases = collections.Counter(p for p, _ in trace)
    outer = collections.Counter(info[a][1][0] for _, a in trace)
    inner = collections.Counter(info[a][1][1] for _, a in trace)
    lines = collections.Counter(f"{info[a][1][3]} ({info[a][1][0]})" for _, a in trace)
    files = collections.Counter(info[a][1][2] for _, a in trace)
    special = collections.Counter(info[a][0] for _, a in trace if info[a][0])
    calls = collections.Counter(info[a][2] for _, a in trace if info[a][2])
    special_at = collections.Counter(
        f"{info[a][0]}: {info[a][1][3]} ({info[a][1][1]} em {info[a][1][0]})"
        for _, a in trace
        if info[a][0]
    )

    cost = {name: c for name, _, c in CLASSES}
    plain = total - sum(special.values())
    est = plain + sum(n * cost[k] for k, n in special.items())

    out = open(env("PERFIL_OUT"), "a", encoding="utf-8")

    def emit(text=""):
        out.write(text + "\n")

    emit(f"## {title}\n")
    emit(f"- Instruções na volta: **{total}** ({kernel_n} no kernel, {total - kernel_n} no anel 3)")
    emit(f"- Kernel na ida: {phases[0]}; na volta: {phases[1]}")
    emit(f"- Endereços distintos: {len(info)}")
    emit(f"- Estimativa grosseira de ciclos num núcleo real: **{est}** "
          f"({plain} instruções comuns a 1 ciclo + as caras abaixo; sem faltas de cache e de TLB)\n")
    emit("### Instruções caras\n")
    emit("| Classe | Quantas | Ciclos estimados (cada) |")
    emit("|---|---:|---:|")
    for name, _, c in CLASSES:
        if special[name]:
            emit(f"| {name} | {special[name]} | {c} |")
    emit("\n### Onde estão as instruções caras\n")
    emit(table(special_at.most_common(), sum(special.values()), 60))
    emit("\n### Por função (símbolo)\n")
    emit(table(outer.most_common(), total, 25))
    emit("\n### Chamadas (funções não inline)\n")
    emit("| | Chamadas |")
    emit("|---|---:|")
    for name, n in calls.most_common(30):
        emit(f"| `{name}` | {n} |")
    emit("\n### Por função inline mais interna\n")
    emit(table(inner.most_common(), total, 30))
    emit("\n### Por arquivo-fonte\n")
    emit(table(files.most_common(), total, 20))
    emit("\n### Por linha\n")
    emit(table(lines.most_common(), total, 40))
    emit()
    out.close()


try:
    main()
finally:
    try:
        gdb.execute("detach", to_string=True)
    except gdb.error:
        pass
