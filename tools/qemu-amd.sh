#!/bin/sh
# QEMU para os boots com `amd-iommu` (ADR 0055; T-510). Até o 10.0, o
# `amd-iommu` do QEMU grava os eventos na memória mas nunca atualiza a cauda
# do log nem o `EventLogInt`, então o kernel não lê falta nenhuma. Compila só
# o x86_64-softmmu do 10.1 em PREFIXO (padrão: target/qemu-amd) e imprime o
# caminho do binário, para `OPTIMUS_QEMU_AMD`.
#
#   OPTIMUS_QEMU_AMD=$(tools/qemu-amd.sh) cargo xtask test iommu
#
# Dependências de compilação (Ubuntu): ninja-build libglib2.0-dev
# libpixman-1-dev libslirp-dev python3-venv flex bison.
set -eu

VERSION=10.1.5
# SHA-256 do tarball, conferido contra a assinatura GPG da versão (chave
# CEAC C9E1 5534 EBAB B82D 3FA0 3353 C9CE F108 B584, Michael Roth).
SHA256=1f1209b4db82e6c4417eaf6e7e0b073563572a042d9fb7492b084ba65a9c0693

PREFIX=${1:-$(pwd)/target/qemu-amd}
BIN="$PREFIX/bin/qemu-system-x86_64"
if [ -x "$BIN" ]; then
    echo "$BIN"
    exit 0
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
curl -sSfL -o "$WORK/qemu.tar.xz" "https://download.qemu.org/qemu-$VERSION.tar.xz"
echo "$SHA256  $WORK/qemu.tar.xz" | sha256sum -c - >&2
tar xJf "$WORK/qemu.tar.xz" -C "$WORK"
cd "$WORK/qemu-$VERSION"
./configure --target-list=x86_64-softmmu --prefix="$PREFIX" \
    --disable-docs --disable-werror --enable-slirp >&2
make -j"$(nproc)" install >&2
echo "$BIN"
