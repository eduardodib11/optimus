//! RFC 8439, seção 2.8.2, casos diferenciais contra o OpenSSL e P6.

use super::*;
use crate::testutil::hex;

fn de_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn chave(s: &str) -> Secret<32> {
    Secret::take(&mut de_hex(s).try_into().unwrap())
}

#[test]
fn rfc8439() {
    let key = chave("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce: [u8; 12] = de_hex("070000004041424344454647").try_into().unwrap();
    let aad = de_hex("50515253c0c1c2c3c4c5c6c7");
    let mut buf = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let tag = seal(&key, &nonce, &aad, &mut buf);
    assert_eq!(hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");
    assert_eq!(hex(&buf[..16]), "d31a8d34648e60db7b86afbc53ef7ec2");
    open(&key, &nonce, &aad, &mut buf, &tag).unwrap();
    assert!(buf.starts_with(b"Ladies and"));
}

/// `(chave, nonce, aad, texto claro, texto cifrado, tag)`.
const CASOS: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "82b70eee7f1a5039bef07ec2347f066ed08f5dc7512447e3404300026b6e5455",
        "94a065685d64c4980bb8d454",
        "",
        "",
        "",
        "3e18685f6963fb83fa502a77f4c22b6a",
    ),
    (
        "4a8721a99a01ad219eb59cf6a15ef6f15a1d830bb7ce09d6bbc004e7175c643c",
        "7decb0b580ec37bc9712dd2e",
        "6a",
        "ae",
        "d1",
        "b8d1e2d3ff26c425a883f193937a4c6c",
    ),
    (
        "b94bae8d2f9fa29c5a284c9ef7521829cf1079b080e9d74a1c10fcab6a4243d3",
        "3656debe4c1ed79648e856e8",
        "f9a2f58c95f0ce4b39c15bffad5c2d",
        "fb8bb820b6119cba8ff88796ae5b05",
        "c87e6fff6f1832dd5006191fd54f04",
        "503c9c5ce0eea25dae95de689b53c805",
    ),
    (
        "f280a68ced93b6b28cb0d1b358e6baab485565b9f49028d557d79a8a0e6451e1",
        "5c705c15f173541b4438a25c",
        "f76312d4eeb3c2246879bf00b3cf8ed1",
        "3abf129a3097ad96b442d6d1bdef4850",
        "3689fd98b17b9d13442dd9289718989d",
        "10a979ea3f7a1797097c9445f63a86e0",
    ),
    (
        "c3f465442eb300c337a648a6c0dbdd73fc95f5c2c451859afe80d40aa39dfb92",
        "49f40c3ee37d961445c806f5",
        "8c7cf2127dfa894f9296fcf33c08409990",
        "ac970dedb3b843120181e9376107dbdaf6",
        "424a22e2b4d66af10259a5df1ccf9a65cc",
        "c04e60612fd985b2c26682cf5d94b019",
    ),
    (
        "c5f3c86497ee219b01dd92f19f4954f4fea94ed9182375882b200daadb23cff9",
        "193f3e70384495e04c5d5ed3",
        "52226d1637c2248f1d3ccc4405dd2ea1fa",
        "fab4bf1c46964d947086207882914478bee8c75b4309ae2b122e3fe87ac7ecf5a5370fc41b4ddb723b2afb6c47c0b57894aab2c5c145b797ddb9126e5cca20",
        "c2622b674e22b1a99207ab976a5951d83e3c6f95130cde0756ac69764bba7a325930fe15527d7178e59ada8f3e47a37eee972f4cd63ff528100c7a05547e0f",
        "71715bd0dbdf805e30fb82cf88df26ae",
    ),
    (
        "3112105f676414faf6b200daf099dba5eeec33624f5124bfc5f04d82388e5292",
        "7810f610b0bca11e0be9f14f",
        "3ca695e87a5311660c7628cdba9f5eefb990",
        "22ef537b596a16dc8a03ec1fe7d2561711b3302479fb2ff11b7c19fecb1e1882d0e49c1a13635bce60772ba0372c52266d08e1b7f9d8c043069de5723b479ff7",
        "48edb2b63ccc2cefebd7645efe7734ab679ef786b6fac2767591b2d18112b95306deaa35dd0fda969403e5a2ca77f3a64f0ca384ac444f3d06fa0fdce19e8989",
        "72f6778f81c1b4f3dd2400b5c218952b",
    ),
    (
        "2c86cea0434229f17d2bdb7d8d1ffc7f186692bf3224d7a0c20092430ee24909",
        "18da8936c342a4219c564686",
        "fea59211200e0e3e1942b6df840876db40b967",
        "a9b706535330895749e4dedb3caaa2e474ecde57e21852f2fb003540d61a6a001078f6b5c9ed6e678d669bb67bbbb47f1ffdcdb249497afac3133056cb329066a5",
        "da17caff9d2ff411a4141892c3f96e1ea273a5e84200a1b1c31457047d9213a05238f16ae77e76c7fa261b6744db53d24d12d82a2bf2bfff60a1c8d10ab8a9c2aa",
        "96b0d9da9120d31f838e5ad06bbf4520",
    ),
    (
        "f4f02e65c005355ec70ba20d9fc4f3cce61f4bd5b90a699192270d2cb6d39d07",
        "8c7824132d99b36af72f3d7a",
        "afd8c901c7c15b6aa4c5a537",
        "bf7f336c969c89275527d35e7320d0d576d9f77d9ad68f2ba95fd70f4c3b975ede61a634a9271ff84625a360efc475f433006350392fab4dbc35e1a55d34bb34216469a5bf58ea2a7dceeec0023cbf4301fdc3af24fb97083bf5b564afc34894ff2d3897d0ac20dd1970d7798a254a8a31f4dd5cc57d2fe7b6422a0248b808",
        "e656c78782dc05396911e27b1e67a0cb12db7a225796a83d473b378b17eb5fa564848d6ce321503f612854af85f3adb34c337f551d384bf8cd7dcd7ace06766b7bb5db52d0937461f7dc6e63fa9a7dec4198cd2168b283df80ad2fb555bd1b04e3f8c282ce9b09a920b555924787ab3121b1591a8e8fa901e7de2d4ebe1029",
        "d5e2131139ee8410333edc02198d5d24",
    ),
    (
        "0a80eac4281b6f63e206f12b8ef00b1b51c9de126e0cd7d3ddc10755ad4b9b61",
        "d827bd6ec9d7618a47f0ba92",
        "013f56ea2725c312d14c6409fc",
        "a2ea45ef7927ba0f075edb2b8843beab6d4d962e913836ccbf9bbcf4e37b47860806c54479f61c04076cd677789d1c7a13c5b10a98e1e6343fbd8dc7c19a5527e51c6cc73299bfd146e9b320fd016ae8151e2d3baf49bfae868df7493f86800c81c6557d86e05a461ab53f04e916fd140dd23cd3e27138202f1522eb9b238b3d",
        "8c91c5bba839518552f15956855a1b5f516a2401f7710fd0972fb595a048cd73dcff2424aebbd3ffb7a26a3393e4cf0d4795cfeaeb056df0db89964a843acb942efbc0be860f7a17181ccfa53c6ec554c81349471065ed6dda1296d82852c176e9a6dc603f9d690f43ac96791ccf8e90d4939b4986b264456d76050db70b7a8a",
        "2c2524b14393594a7658291312c6a091",
    ),
    (
        "cf9c84e8989900a5feeec24f6e86a169ea2d4cb428d9e0ca596447fb56e4b008",
        "4ade89fc6e7a56d680a09637",
        "6484d9b787f92c3b38ac3134915b",
        "19c458ab8533d1a8319f2095acd2d120219a235c1430d035ecd52473d70d9437a5b926eec234577d3a302ac2df3a8b9ce8db146b44c35c62a624479c1bee9ce282915583e9f0ce324467ea34e377447f552de483ed53f6359880b61a3e690cacf6fa90aa1d9344d796d4bd4194631000f9519fd590d7ecaea70751fd00f7eebf16",
        "fd57ed0ed3e246bd5fa11c309c2d99426e650cd66ceca4fe67ea779b61875520d922b8183ba316dd25f698afcbd81362a3815ef7618b168abd37fda6775c10e803e420fafd05777a311cf1b24a018f9c27a475f696ae8a6a649a651ce78cacf9b54cb6c9612aa38be7054b22e77ba3ea6a68106a9c57ace560e6c0c31f1da4cee7",
        "468e6d6d4a52f9367d82bcdaf492e248",
    ),
    (
        "7401f53d67565779cc34c5d5758c05687822bfde9c7230bee31f85014bd91ded",
        "0761613658eae0f0f494260c",
        "ee680ae36721ae6633bd2d5870ca0111",
        "db1d9960c7c8553ac4606f43cee64bd10d8ce967882f77d8d5e36167a780176252bb30ddb949935d034cd93503eea628f94dbc031dbdf487e7a8d357c9dae10875f5963724f7702aa03029a6d059a4b3159e3f2a2b14f9f06ee29b4dd98ee6247c942e9a25c095d33151b1d92daf6bb635eca632fea712e71d74929e87ebb12fe7d364cfda3f4320e0a5139cbad7375904e4499c1537182229969591dd7611dde99752aacaeeec135abbf2a32d38e08bbdae3bc7cde687424aeab68e5c58d204cda182634fdfe83c",
        "e99ec0ab8ced69b0f508b5c9cbffef093fbc2dff22c5d869a4a9f19a6e4e3b2169af8975151b4e3740c1d78895b1d3fe24e557fbe92c0218bb754689bee6148f7eb656765db91833c7862f8b2560ff5b7b073616264bd981d9872afa0e2db300c4619eb805f6633652727aa3040bf4b502fb65ac84b70e4aaa08b8b30cfdbffb6446ac7181170223b5b8d4ed2b9d54671fceade5d3d0a3b813b35b571c1e32b4b075ce59149a5d66775c81928b4e5402fb537cc6f2ccfe87ff34acfc42045aa4e5fe7330db0a1d3a",
        "f0b6b39fdd9d3a4079c34b6928f4cf28",
    ),
];

#[test]
fn diferencial() {
    for (k, n, a, p, c, t) in CASOS {
        let (key, aad) = (chave(k), de_hex(a));
        let nonce: [u8; 12] = de_hex(n).try_into().unwrap();
        let mut buf = de_hex(p);
        let tag = seal(&key, &nonce, &aad, &mut buf);
        assert_eq!((hex(&buf), hex(&tag)), (c.to_string(), t.to_string()));
        open(&key, &nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(hex(&buf), *p);
    }
}

/// P6: inverter qualquer byte da tag, do texto cifrado ou do AAD recusa
/// e deixa o buffer zerado.
#[test]
fn adulteracao_recusada_e_buffer_zerado() {
    let key = chave("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = [5u8; 12];
    let aad = *b"cabecalho";
    let mut ct = [0x42u8; 40];
    let tag = seal(&key, &nonce, &aad, &mut ct);
    for i in 0..TAG_LEN {
        let mut ruim = tag;
        ruim[i] ^= 1;
        let mut b = ct;
        assert_eq!(open(&key, &nonce, &aad, &mut b, &ruim), Err(AuthError));
        assert_eq!(b, [0; 40], "tag byte {i}");
    }
    for i in 0..ct.len() {
        let mut b = ct;
        b[i] ^= 1;
        assert_eq!(open(&key, &nonce, &aad, &mut b, &tag), Err(AuthError));
        assert_eq!(b, [0; 40], "dado byte {i}");
    }
    let mut b = ct;
    assert_eq!(
        open(&key, &nonce, b"cabecalhx", &mut b, &tag),
        Err(AuthError)
    );
    assert_eq!(b, [0; 40]);
}
