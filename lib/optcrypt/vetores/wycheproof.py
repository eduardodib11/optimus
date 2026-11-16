#!/usr/bin/env python3
"""Converte um arquivo JSON do Wycheproof (C2SP/wycheproof, testvectors_v1)
para o formato compacto lido pelos testes do optcrypt.

Formato: uma linha por grupo (`G campo...`) seguida das linhas dos testes
(`T tcId resultado campo...`), com os campos em hexadecimal e `-` para vazio.
O resultado é `v` (valid), `i` (invalid) ou `a` (acceptable). Números
inteiros viram hexadecimal sem sinal.

Uso: wycheproof.py entrada.json 'campos.do.grupo' 'campos.do.teste' > saida.txt
Exemplo: wycheproof.py hmac_sha384_test.json 'tagSize' 'key,msg,tag'
Um campo com ponto (`publicKey.uncompressed`) desce nos objetos aninhados.
"""
import json
import sys


def valor(obj, caminho):
    for parte in caminho.split("."):
        obj = obj[parte]
    if isinstance(obj, int):
        obj = "%x" % obj
        if len(obj) % 2:
            obj = "0" + obj
    return obj if obj else "-"


def main():
    entrada, grupo, teste = sys.argv[1], sys.argv[2], sys.argv[3]
    dados = json.load(open(entrada))
    gcampos = [c for c in grupo.split(",") if c]
    tcampos = [c for c in teste.split(",") if c]
    print("# %s, %s (%d testes)" % (dados["algorithm"], entrada.rsplit("/", 1)[-1], dados["numberOfTests"]))
    for g in dados["testGroups"]:
        print(" ".join(["G"] + [valor(g, c) for c in gcampos]))
        for t in g["tests"]:
            res = {"valid": "v", "invalid": "i", "acceptable": "a"}[t["result"]]
            print(" ".join(["T", str(t["tcId"]), res] + [valor(t, c) for c in tcampos]))


main()
