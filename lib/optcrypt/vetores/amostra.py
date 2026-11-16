#!/usr/bin/env python3
"""Amostra de um arquivo já convertido por wycheproof.py: mantém o
cabeçalho, os grupos e os N primeiros casos de cada resultado (válido,
inválido, aceitável). Uso: amostra.py N < entrada.txt > saida.txt"""
import sys

n = int(sys.argv[1])
vistos = {}
for linha in sys.stdin:
    if linha.startswith("T "):
        res = linha.split(" ")[2]
        vistos[res] = vistos.get(res, 0) + 1
        if vistos[res] > n:
            continue
    if linha.startswith("#"):
        linha = linha.rstrip("\n") + " (amostra: até %d casos de cada resultado)\n" % n
    sys.stdout.write(linha)
