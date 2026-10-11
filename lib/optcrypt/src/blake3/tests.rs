//! Vetores oficiais do BLAKE3 (`test_vectors/test_vectors.json` do
//! repositório BLAKE3-team/BLAKE3): a entrada de tamanho `n` é a sequência
//! 0, 1, ..., 250, 0, 1, ... e as saídas são os primeiros 32 bytes de cada
//! modo (hash, hash com chave e derivação de chave).

use std::fmt::Write;

use super::*;

const KEY: &[u8; KEY_LEN] = b"whats the Elvish word for friend";
const CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

/// `(tamanho, hash, keyed_hash, derive_key)`.
const CASES: &[(usize, &str, &str, &str)] = &[
    (
        0,
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
        "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
    ),
    (
        1,
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
        "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c",
    ),
    (
        63,
        "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae",
        "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3",
    ),
    (
        64,
        "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6",
        "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e",
    ),
    (
        65,
        "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
        "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72",
        "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8",
    ),
    (
        1023,
        "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
        "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5",
    ),
    (
        1024,
        "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
        "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706",
    ),
    (
        1025,
        "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
        "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb",
    ),
    (
        2048,
        "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1",
        "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23",
    ),
    (
        2049,
        "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
        "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5",
        "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273",
    ),
    (
        3072,
        "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
        "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770",
        "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b",
    ),
    (
        3073,
        "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
        "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a",
        "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081",
    ),
    (
        4096,
        "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
        "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0",
        "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9",
    ),
    (
        8193,
        "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b",
        "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5",
        "af1e0346e389b17c23200270a64aa4e1ead98c61695d917de7d5b00491c9b0f1",
    ),
    (
        31744,
        "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
        "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419",
        "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e",
    ),
    (
        102_400,
        "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
        "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7",
        "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6",
    ),
];

/// Saída estendida (131 bytes) do hash da entrada de 1025 bytes.
const XOF_1025: &str = "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444\
f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bf\
e332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e562\
7be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff1280\
0ab67a";

fn input(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[test]
fn vetores_oficiais() {
    for &(len, h, keyed, derive) in CASES {
        let data = input(len);
        assert_eq!(hex(&hash(&data)), h, "hash de {len} bytes");
        let k = Hasher::new_keyed(KEY).update(&data).finalize();
        assert_eq!(hex(&k), keyed, "keyed_hash de {len} bytes");
        let d = Hasher::new_derive_key(CONTEXT).update(&data).finalize();
        assert_eq!(hex(&d), derive, "derive_key de {len} bytes");
    }
}

#[test]
fn saida_estendida() {
    let mut out = [0u8; 131];
    Hasher::new().update(&input(1025)).finalize_xof(&mut out);
    assert_eq!(hex(&out), XOF_1025);
}

#[test]
fn incremental_em_pedacos_de_qualquer_tamanho() {
    let data = input(9000);
    let whole = hash(&data);
    for step in [1, 7, 64, 100, 1024, 1500, 4096] {
        let mut h = Hasher::new();
        for part in data.chunks(step) {
            h.update(part);
        }
        assert_eq!(h.finalize(), whole, "passo {step}");
    }
}
