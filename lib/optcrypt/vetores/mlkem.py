#!/usr/bin/env python3
"""Converte os vetores do ML-KEM-768 para o formato compacto dos testes
(o mesmo de wycheproof.py: linhas `G seção` e `T id resultado campo...`).

Para caber no repositório, saídas grandes que o teste só compara viram
SHA3-256 (`H(...)`), e só uma parte dos casos de cada fonte entra.

Uso: mlkem.py acvp ML-KEM-keyGen-FIPS203.json ML-KEM-encapDecap-FIPS203.json
     mlkem.py wycheproof mlkem_768_test.json mlkem_768_encaps_test.json
As entradas vêm de usnistgov/ACVP-Server (gen-val/json-files, arquivos
internalProjection.json) e de C2SP/wycheproof (testvectors_v1).
"""
import hashlib
import json
import sys


def h(x):
    return hashlib.sha3_256(bytes.fromhex(x)).hexdigest()


def grupos(arq, filtro):
    return [g for g in json.load(open(arq))["testGroups"] if filtro(g)]


def acvp(keygen, encdec):
    print("# ML-KEM-768, ACVP-Server (FIPS 203): keyGen e encapDecap")
    p768 = lambda g: g["parameterSet"] == "ML-KEM-768"
    for g in grupos(keygen, p768):
        print("G keygen")
        for t in g["tests"]:
            print("T", t["tcId"], "v", t["d"], t["z"], h(t["ek"]), h(t["dk"]))
    for g in grupos(encdec, p768):
        f = g["function"]
        print("G", f)
        for t in g["tests"][:10]:
            if f == "encapsulation":
                campos = [t["ek"], t["m"], h(t["c"]), t["k"]]
            elif f == "decapsulation":
                campos = [t["dk"], t["c"], t["k"]]
            elif f == "encapsulationKeyCheck":
                campos = [t["ek"]]
            else:
                campos = [t["dk"]]
            res = "i" if t.get("testPassed") is False else "v"
            print(" ".join(["T", str(t["tcId"]), res] + campos))


def wycheproof(dec, enc):
    print("# ML-KEM-768, Wycheproof: mlkem_768_test (amostra) e mlkem_768_encaps_test (ModulusOverflow)")
    print("G decaps")
    for g in grupos(dec, lambda g: True):
        validos = [t for t in g["tests"] if t["result"] == "valid"]
        if g["source"]["name"] == "FIPS 203":
            validos = validos[:10]
        for t in validos:
            print("T", t["tcId"], "v", t["seed"], h(t["ek"]), t["c"], t["K"])
    print("G encaps")
    for g in grupos(enc, lambda g: True):
        for t in g["tests"]:
            if "ModulusOverflow" in t["flags"]:
                print("T", t["tcId"], "i", t["ek"], t["m"])


{"acvp": acvp, "wycheproof": wycheproof}[sys.argv[1]](sys.argv[2], sys.argv[3])
