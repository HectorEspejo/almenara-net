//! Huella JA4 de cliente TLS/QUIC según la especificación pública de FoxIO (§7.4).
//!
//! Se implementa solo la parte de cliente (JA4), no JA4S/JA4H/JA4X. Los valores
//! GREASE se ignoran en todas las listas (versiones, cifrados, extensiones y
//! algoritmos de firma), como exige la especificación. Los vectores de prueba
//! oficiales de FoxIO, extraídos de sus pcaps, mandan en los casos límite
//! (ALPN no ASCII, listas vacías, extensiones GREASE).

use sha2::{Digest, Sha256};

use crate::inference::tls::ClientHello;

/// Tipo de extensión server_name (SNI).
const EXT_SERVER_NAME: u16 = 0x0000;
/// Tipo de extensión ALPN.
const EXT_ALPN: u16 = 0x0010;
/// Valor usado para los hashes cuando la lista correspondiente está vacía.
const HASH_VACIO: &str = "000000000000";
/// Dígitos hexadecimales en minúscula para componer los hashes.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Transporte de la huella: `t` (TCP) o `q` (QUIC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4Transport {
    /// TLS sobre TCP.
    Tcp,
    /// QUIC.
    Quic,
}

impl Ja4Transport {
    /// Prefijo de la huella.
    pub fn prefix(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
        }
    }
}

/// Calcula la huella JA4 de cliente `t…` (TCP) o `q…` (QUIC).
pub fn compute(hello: &ClientHello, transport: Ja4Transport) -> String {
    let version = version_elegida(hello);
    let cifrados: Vec<u16> = hello
        .ciphers
        .iter()
        .copied()
        .filter(|cifrado| !is_grease(*cifrado))
        .collect();
    let extensiones: Vec<u16> = hello
        .extensions
        .iter()
        .copied()
        .filter(|extension| !is_grease(*extension))
        .collect();

    let prefijo = format!(
        "{transporte}{version}{sni}{cifrados:02}{extensiones:02}{alpn}",
        transporte = transport.prefix(),
        version = codigo_version(version),
        sni = if hello.sni.is_some() { 'd' } else { 'i' },
        cifrados = cifrados.len().min(99),
        extensiones = extensiones.len().min(99),
        alpn = prefijo_alpn(hello),
    );

    let hash_cifrados = if cifrados.is_empty() {
        HASH_VACIO.to_string()
    } else {
        let mut lista: Vec<String> = cifrados
            .iter()
            .map(|cifrado| format!("{cifrado:04x}"))
            .collect();
        lista.sort();
        hash12(&lista.join(","))
    };

    let mut extensiones_ordenadas: Vec<String> = extensiones
        .iter()
        .filter(|extension| **extension != EXT_SERVER_NAME && **extension != EXT_ALPN)
        .map(|extension| format!("{extension:04x}"))
        .collect();
    extensiones_ordenadas.sort();
    let algoritmos: Vec<String> = hello
        .signature_algorithms
        .iter()
        .copied()
        .filter(|algoritmo| !is_grease(*algoritmo))
        .map(|algoritmo| format!("{algoritmo:04x}"))
        .collect();
    let hash_extensiones = if extensiones_ordenadas.is_empty() {
        HASH_VACIO.to_string()
    } else {
        let mut texto = extensiones_ordenadas.join(",");
        if !algoritmos.is_empty() {
            texto.push('_');
            texto.push_str(&algoritmos.join(","));
        }
        hash12(&texto)
    };

    format!("{prefijo}_{hash_cifrados}_{hash_extensiones}")
}

/// Versión con la que se etiqueta la huella: la más alta de supported_versions
/// que no sea GREASE; si no hay ninguna, la versión heredada del ClientHello.
fn version_elegida(hello: &ClientHello) -> u16 {
    let mut elegida: Option<u16> = None;
    for version in &hello.supported_versions {
        if is_grease(*version) {
            continue;
        }
        elegida = Some(match elegida {
            Some(actual) => actual.max(*version),
            None => *version,
        });
    }
    elegida.unwrap_or(hello.legacy_version)
}

/// Código de versión de dos caracteres de JA4.
fn codigo_version(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// Primer y último carácter del primer protocolo ALPN.
///
/// Si no hay ALPN, el primer protocolo está vacío o el carácter no es ASCII, se
/// sustituye por el marcador que fija la especificación: "00" para la ausencia y
/// '9' para los caracteres no ASCII (así lo hacen las implementaciones oficiales
/// y lo confirma el vector tls-non-ascii-alpn.pcapng).
fn prefijo_alpn(hello: &ClientHello) -> String {
    let Some(protocolo) = hello.alpn.first() else {
        return "00".to_string();
    };
    if protocolo.is_empty() {
        return "00".to_string();
    }
    let primero = caracter_alpn(protocolo.chars().next());
    let ultimo = caracter_alpn(protocolo.chars().next_back());
    format!("{primero}{ultimo}")
}

/// Normaliza un carácter de ALPN al marcador de JA4.
fn caracter_alpn(caracter: Option<char>) -> char {
    match caracter {
        Some(caracter) if caracter.is_ascii() => caracter,
        _ => '9',
    }
}

/// SHA-256 del texto en minúsculas, truncado a sus primeros 12 caracteres hex.
fn hash12(texto: &str) -> String {
    let digest = Sha256::digest(texto.as_bytes());
    let mut salida = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        salida.push(HEX[usize::from(byte >> 4)] as char);
        salida.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    salida
}

/// Indica si un valor de 16 bits es un GREASE de TLS.
pub fn is_grease(value: u16) -> bool {
    (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::tls::parse_client_hello;

    /// Decodifica una cadena hexadecimal (sin separadores) a bytes.
    fn bytes_hex(texto: &str) -> Vec<u8> {
        texto
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|par| {
                let par = std::str::from_utf8(par).expect("el hexadecimal es ASCII");
                u8::from_str_radix(par, 16).expect("dígito hexadecimal válido")
            })
            .collect()
    }

    /// Vector oficial de FoxIO (pcap tls12.pcap, flujo 0): ClientHello de Firefox.
    /// JA4 esperado: t13d1715h2_5b57614c22b0_3d5424432f57
    const VECTOR_TLS12: &str = concat!(
    "1603010200010001fc0303ecb2691addb2bf6c599c7aaae23de5f42561cc04eb41029acc6fc050a16ac1d22046f8617b",
    "580ac9358e2aa44e306d52466bcc989c87c8ca64309f5faf50ba7b4d0022130113031302c02bc02fcca9cca8c02cc030",
    "c00ac009c013c014009c009d002f00350100019100000021001f00001c636f6e74696c652e73657276696365732e6d6f",
    "7a696c6c612e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010",
    "000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00",
    "208909858fbeb6ed2f1248ba5b9e2978bead0e840110192c61daed0096798b184400170041044d183d91f5eed35791fa",
    "982464e3b0214aaa5f5d1b78616d9b9fbebc22d11f535b2f94c686143136aa795e6e5a875d6c08064ad5b76d44caad76",
    "6e2483012748002b00050403040303000d0018001604030503060308040805080604010501060102030201002d000201",
    "01001c000240010015007a00000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000",
);

    /// Vector oficial de FoxIO (pcap sigalg-grease.pcapng): GREASE en todas las listas.
    /// JA4 esperado: t13d1517h2_8daaf6152771_cb7bf5808d99
    const VECTOR_GREASE: &str = concat!(
    "16030107f2010007ee0303a82668ac70f870a2e6970ee0673b9f35146007a12457f2fd59381f1472d80bab2019d133a9",
    "d13494e1f84db777e27b2ca38cc64e272de76a393cbf5a7871aea6dd00204a4a130113021303c02bc02fc02cc030cca9",
    "cca8c013c014009c009d002f0035010007857a7a0000fe0d011a00000100018f002099a65a3b5549803fce7709dd6563",
    "0af649011ef2f49b84de3b4c76dffded437900f05c76974bcb95fb248e39bdf5702944026dc2a586f3606136fffc2993",
    "6df82dead4d0442e8b3cedaba29baf4720dd2b24f2950694b57c41574df82fb88b5b19dabd7bbe28a95b0570a7acda47",
    "d9b052f9748942a5436f7912b862989f6d865d502570eac5718b3ef4504f22cc4abb2f132dfff09c07ac6a95218f6527",
    "4e3361dbcb71e7d7df52d6df17a5e4e80943525e04e8214d5296bfd127b8cf57e10f7f5e049c7bd69ca52898db146c3d",
    "d33f3a4b1a62f614953d0caba9e68b6ca05a9b455594f7b0543e7c3ff0ad3fdd17d3ee57696f09c4dc44e199581bdd37",
    "1354615787e37b744694ae35e1e310a9b231e0e80010000e000c02683208687474702f312e3100170000003304ef04ed",
    "dada00010011ec04c05b4ba33e87c96d4664e4c2ab1360122306bf633648a5d48ce837abd5fb0fa28cc032d5a2d57209",
    "93a8cc13482b1cd676e629abbfe9cd78eb971c7cadebe301bb01451c2062013211c5dca8b610347d3422c9e971f66056",
    "280ab7d9bb3d07318b87470e15b503cb1488387b4839828cd74495767bc873152c9637cc4920af631352986a91e9263d",
    "1948259de86e020699d246c92fe9c28e523edec610781341bc727500c370a3d5a0a91295d43012c3763d9fda1d99293d",
    "8026334f30a2c342512e81cc41c41d171a7582a1c8a8452c71097c24acb4b0e0178d181cec75a293f46b7be55d6d7167",
    "da07666f1355d086aca5bb2e00c61532700390f17347d0cd057b4f6c515cfbcb4f0974108fd5165dd17ccab4ab2c0569",
    "a68321183a7f947554d4202d7fac3414b31a7ab04c1eb92f77e334700482ae356caa908770117a3f7c8621915ae6f06f",
    "d13b7a00546ec4b227b31bc912e17f3eeaca68f98c5f0783f7b3131307734021b7dcd718467b8406e0bb4f67263e497a",
    "59cb6a4966682b9c6ccb661fc83c04600c9e97f09ae3e0ca69c57f342245a2f5597ad49a90807e2c8b8cc16479d66b5a",
    "38212034f1acd2a7a29ff8074eac1bfd0c4e6a53851da5c8a5a289b81ab1f36b578157ca9d242af512bbd80a9cce4540",
    "c376c2815a7417a6496727322990451eb504245c7cb386573b7c1aa4275c97564bfdcb75c1d73cad080f042bc46cd1b9",
    "6aa57d143ab31b35b615ab6a9547bb08033285f2788420000f6b452a392d42c28d2473b9f8fa0c459ab553ca5c1ea60d",
    "898c45b377cd39b6c1f454a62e0424e1b208686a3ea3b79ab9b17770d8972dd685a8f55999631e4bc2bf81a78584e4af",
    "f8933cca857fac344b75774b273a7242035608f34505b16f10d44379fc764f541401ac65a903cca2f81281ecb07c76c0",
    "525014f8624022597d2ec787b2a4ad4bba683062c2b32b3d91f35c419a3800128fc9666140b17085a329344b4daaa742",
    "0f66ce3f349fe8d33b1f20461069a6f3b40f6f720ac1db452f160b07db53e6bc0808c97306193617d78aa694484b328a",
    "64131dea2733e5e8ce76c4b293648f860b3422a7305b89aac2605d838a04d2d799b5e99e7e79c1d091b9aac8b242a277",
    "83a5330189ac8d9baa3cd57a945a82c00489db6a4200ac1748d25ee0f219fe20b33bc5c20bc0abdc1846d6317be38232",
    "50d0697e8c5dc75880f292cad191978b4158889b3bd3a48e83f61467825522f38971a55bff9b0be4bb8cb5eb36b52a72",
    "93837eeea8b38598ceb4822c4ca53fe628084184b4babaa1a4db6773db30fda0acbe142b34c01cbbe3969ea6ad7a5776",
    "fee226d9a9429f4915bef78dba562ddd9069584832deb4870a8c57ce2c55ceb2678fc42c5de356a35713f8d361ff0852",
    "057957b1e9881364455ed516518c562c3599d8da20657b40721b69066854cfb23fda08ce8f00c96bf340657644c3bc97",
    "64a17229f79004053348ba8dcc35b8249ab957141709152ed8997cda62be83a576ce18a9c9cc389417c8bbfc318c5aa1",
    "69c159370b9b28692cbf485aed289f020751761b2353604a18bb569de64a1c68a33a237c4ae0625fc0707c0a8d8f3021",
    "be4b7e5da35dd3e67011c46a3a0ae8f6b8ce8ce9088ed6471f6fbdaaa34a284332312b784d77296d9eda5e57f1bb2dbb",
    "e65bc29bf9278f5593511059ba850f06abdbf4df4683ed0650001d00201916be8d0e04e95930ef363ca8231b7ff8e5a2",
    "d8192b0588ddc4eb66a38d4e0244cd00050003026832ff01000100000a000c000adada11ec001d00170018000d001a00",
    "180a0a0904090509060403080404010503080505010806060100230000002b000706fafa03040303000b00020100ca34",
    "00ba00b804d679090b08839a648c9b2d010b04d679090f0582df1302060582df1302120582df13021304d67909060582",
    "df13020f04d679090a04d679090d08839a648c9b2d011204d67909010582df13020104d67909040582df13021404d679",
    "090508839a648c9b2d01130582df13020e04d679090708839a648c9b2d01080582df13020d08839a648c9b2d010904d6",
    "79090808839a648c9b2d010c04d679090c08839a648c9b2d010708839a648c9b2d010a08839a648c9b2d010d002d0002",
    "01010000002800260000236f7074696d697a6174696f6e67756964652d70612e676f6f676c65617069732e636f6d0005",
    "00050100000000001b0003020002001200006a6a000100",
);

    /// Vector oficial de FoxIO (pcap tls-non-ascii-alpn.pcapng): ALPN no ASCII.
    /// JA4 esperado: t13d151699_8daaf6152771_e5627efa2ab1
    const VECTOR_ALPN_NO_ASCII: &str = concat!(
    "1603010200010001fc03030f9e38acb9a54a7c6e00e29a70ac2feee180ff76d7f25dca84932a66a42d1e5a20bc58b92f",
    "865e6b9aa4a6371cadcb0afe1da1c0f705209a11d52357f56d5dd9620020aaaa130113021303c02bc02fc02cc030cca9",
    "cca8c013c014009c009d002f0035010001939a9a0000ff010001000033002b00290a0a000100001d0020cf55af2603e9",
    "2f59eb321779706a18fa6b96b16c16404c2264ed687a59401878002d0002010100050005010000000044690005000302",
    "6832000d00120010040308040401050308050501080606010010000e000c02baad08687474702f312e3100230000001b",
    "0003020002002b0007060a0a0304030300000022002000001d636c69656e7473657276696365732e676f6f676c656170",
    "69732e636f6d00120000000a000a00080a0a001d0017001800170000000b000201006a6a000100001500ba0000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000",
);

    /// Vector oficial de FoxIO (pcap tls-handshake.pcapng, flujo 5): ALPN http/1.1.
    /// JA4 esperado: t13d1516h1_8daaf6152771_e5627efa2ab1
    const VECTOR_H1: &str = concat!(
    "1603010200010001fc03033f57def90400ffa48568b4c59c0d1b211eea65d93ed25e6797e2f142171682a02028f89763",
    "feb4ce3d63b25210d744621b7e334cf99ea58da273e57b06804d46c300204a4a130113021303c02bc02fc02cc030cca9",
    "cca8c013c014009c009d002f003501000193aaaa0000000d00120010040308040401050308050501080606010033002b",
    "0029aaaa000100001d0020b15c4efe2dbf4846ff2b6636610aedfe050b3e5a1db825b45869ddf77a68dd250000002400",
    "2200001f6c702d707573682d7365727665722d3435322e6c617374706173732e636f6dff01000100002b000706aaaa03",
    "04030300230000002d0002010100050005010000000000120000000b0002010000170000446900050003026832001000",
    "0b000908687474702f312e31001b0003020002000a000a0008aaaa001d001700181a1a000100001500bb000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000",
);

    /// ClientHello del ejemplo de la especificación pública de FoxIO.
    fn client_hello_de_la_especificacion() -> ClientHello {
        ClientHello {
            legacy_version: 0x0303,
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
            supported_versions: vec![0x0304, 0x0303],
            ciphers: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023,
                0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
            ],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
        }
    }

    #[test]
    fn calcula_el_ejemplo_oficial_de_la_especificacion() {
        let hello = client_hello_de_la_especificacion();
        assert_eq!(
            compute(&hello, Ja4Transport::Tcp),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
    }

    #[test]
    fn usa_el_prefijo_de_quic_sin_cambiar_el_resto() {
        let hello = client_hello_de_la_especificacion();
        let tcp = compute(&hello, Ja4Transport::Tcp);
        let quic = compute(&hello, Ja4Transport::Quic);
        assert!(quic.starts_with('q'));
        assert_eq!(&quic[1..], &tcp[1..]);
    }

    #[test]
    fn coincide_con_el_vector_oficial_tls12() {
        let hello = parse_client_hello(&bytes_hex(VECTOR_TLS12)).expect("vector oficial TLS 1.2");
        assert_eq!(
            compute(&hello, Ja4Transport::Tcp),
            "t13d1715h2_5b57614c22b0_3d5424432f57"
        );
    }

    #[test]
    fn coincide_con_el_vector_oficial_con_grease() {
        let hello =
            parse_client_hello(&bytes_hex(VECTOR_GREASE)).expect("vector oficial con GREASE");
        // El vector trae GREASE en versiones, cifrados, extensiones y algoritmos de firma.
        assert!(hello.ciphers.iter().any(|cifrado| is_grease(*cifrado)));
        assert!(hello
            .extensions
            .iter()
            .any(|extension| is_grease(*extension)));
        assert!(hello
            .signature_algorithms
            .iter()
            .any(|algoritmo| is_grease(*algoritmo)));
        assert!(hello
            .supported_versions
            .iter()
            .any(|version| is_grease(*version)));
        assert_eq!(
            compute(&hello, Ja4Transport::Tcp),
            "t13d1517h2_8daaf6152771_cb7bf5808d99"
        );
    }

    #[test]
    fn coincide_con_el_vector_oficial_de_alpn_no_ascii() {
        let hello = parse_client_hello(&bytes_hex(VECTOR_ALPN_NO_ASCII))
            .expect("vector oficial ALPN no ASCII");
        assert_eq!(
            compute(&hello, Ja4Transport::Tcp),
            "t13d151699_8daaf6152771_e5627efa2ab1"
        );
    }

    #[test]
    fn coincide_con_el_vector_oficial_de_alpn_http1() {
        let hello =
            parse_client_hello(&bytes_hex(VECTOR_H1)).expect("vector oficial ALPN http/1.1");
        assert_eq!(
            compute(&hello, Ja4Transport::Tcp),
            "t13d1516h1_8daaf6152771_e5627efa2ab1"
        );
    }

    #[test]
    fn sin_cifrados_ni_extensiones_usa_los_marcadores_vacios() {
        let hello = ClientHello {
            legacy_version: 0x0303,
            ..ClientHello::default()
        };
        assert_eq!(
            compute(&hello, Ja4Transport::Tcp),
            "t12i000000_000000000000_000000000000"
        );
    }

    #[test]
    fn el_alpn_aporta_el_primer_y_ultimo_caracter() {
        fn prefijo(alpn: &[&str]) -> String {
            let hello = ClientHello {
                alpn: alpn.iter().map(|protocolo| protocolo.to_string()).collect(),
                ..ClientHello::default()
            };
            compute(&hello, Ja4Transport::Tcp)
                .split('_')
                .next()
                .expect("la huella tiene prefijo")
                .to_string()
        }
        assert_eq!(prefijo(&["h2"]), "t00i0000h2");
        assert_eq!(prefijo(&["http/1.1"]), "t00i0000h1");
        assert_eq!(prefijo(&["x"]), "t00i0000xx");
        assert_eq!(prefijo(&["7"]), "t00i000077");
        assert_eq!(prefijo(&[""]), "t00i000000");
        assert_eq!(prefijo(&["", "h2"]), "t00i000000");
        assert_eq!(prefijo(&[]), "t00i000000");
        assert_eq!(prefijo(&["é"]), "t00i000099");
    }

    #[test]
    fn usa_la_version_mas_alta_no_grease() {
        let hello = ClientHello {
            legacy_version: 0x0303,
            supported_versions: vec![0x0a0a, 0x0303, 0x0304, 0x1a1a],
            ..ClientHello::default()
        };
        let huella = compute(&hello, Ja4Transport::Tcp);
        assert!(huella.starts_with("t13i000000_"), "{huella}");
    }

    #[test]
    fn una_version_desconocida_se_marca_como_00() {
        let hello = ClientHello {
            legacy_version: 0x9999,
            ..ClientHello::default()
        };
        assert!(compute(&hello, Ja4Transport::Tcp).starts_with("t00i000000_"));
    }

    #[test]
    fn los_hashes_tienen_doce_caracteres_hexadecimales_en_minuscula() {
        let huella = compute(&client_hello_de_la_especificacion(), Ja4Transport::Tcp);
        let mut partes = huella.split('_').skip(1);
        for parte in [partes.next(), partes.next()] {
            let parte = parte.expect("la huella tiene tres partes");
            assert_eq!(parte.len(), 12);
            assert!(
                parte
                    .chars()
                    .all(|caracter| caracter.is_ascii_hexdigit() && !caracter.is_ascii_uppercase()),
                "{parte}"
            );
        }
        assert!(partes.next().is_none());
    }

    #[test]
    fn detecta_los_dieciseis_valores_grease() {
        for valor in [
            0x0a0a_u16, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
            0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ] {
            assert!(is_grease(valor), "{valor:04x}");
        }
        for valor in [0x0000_u16, 0x0304, 0x0a0b, 0x0a1a, 0x1301, 0xffff] {
            assert!(!is_grease(valor), "{valor:04x}");
        }
    }
}
