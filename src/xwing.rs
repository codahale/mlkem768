//! An implementation of the `X-Wing` hybrid post-quantum/classical key encapsulation algorithm.

use rand_core::CryptoRngCore;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Generates an encapsulation key and a corresponding decapsulation key using the given RNG.
///
/// The decapsulation key must be kept secret.
pub fn key_gen(mut rng: impl CryptoRngCore) -> ([u8; 1184 + 32], [u8; 2400 + 32 + 32]) {
    let (mut d, mut z, mut x) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    rng.fill_bytes(&mut d);
    rng.fill_bytes(&mut z);
    rng.fill_bytes(&mut x);
    key_gen_det(d, z, x)
}

/// Deterministically generates an encapsulation key and corresponding decapsulation key given a
/// seed value.
fn key_gen_det(d: [u8; 32], z: [u8; 32], x: [u8; 32]) -> ([u8; 1184 + 32], [u8; 2400 + 32 + 32]) {
    // Derive a ML-KEM-768 key pair.
    let (pk_m, sk_m) = crate::kem_key_gen(d, z);

    // Derive an X25519 key pair.
    let sk_x = StaticSecret::from(x);
    let pk_x = PublicKey::from(&sk_x);

    // Concatenate the two public keys.
    let mut pk = [0u8; 1184 + 32];
    pk[..pk_m.len()].copy_from_slice(&pk_m);
    pk[pk_m.len()..].copy_from_slice(pk_x.as_bytes());

    // Concatenate the two private keys along with the X25519 public key.
    let mut sk = [0u8; 2400 + 32 + 32];
    sk[..sk_m.len()].copy_from_slice(&sk_m);
    sk[sk_m.len()..sk_m.len() + 32].copy_from_slice(sk_x.as_bytes());
    sk[sk_m.len() + 32..].copy_from_slice(pk_x.as_bytes());

    (pk, sk)
}

/// Generates a ciphertext and an associated shared key from an encapsulation key and an RNG. If the
/// encapsulation key is not valid, returns `None`.
///
/// The shared key must be kept secret.
pub fn encapsulate(
    pk: &[u8; 1184 + 32],
    mut rng: impl CryptoRngCore,
) -> Option<([u8; 1088 + 32], [u8; 32])> {
    let (mut m, mut z) = ([0u8; 32], [0u8; 32]);
    rng.fill_bytes(&mut m);
    rng.fill_bytes(&mut z);
    encapsulate_det(pk, m, z)
}

/// Deterministically generates a ciphertext and associated shared key from an encapsulation key and
/// a seed value.
fn encapsulate_det(
    pk: &[u8; 1184 + 32],
    m: [u8; 32],
    z: [u8; 32],
) -> Option<([u8; 1088 + 32], [u8; 32])> {
    // Encapsulate a key with ML-KEM-768.
    let pk_m = pk[..1184].try_into().expect("should be 1184 bytes");
    let (ct_m, ss_m) = crate::kem_encapsulate(&pk_m, m)?;

    // Generate an ephemeral X25519 key pair.
    let sk_e = StaticSecret::from(z);
    let pk_e = PublicKey::from(&sk_e).to_bytes();

    // Calculate the X25519 ephemeral shared secret.
    let pk_x: [u8; 32] = pk[1184..].try_into().expect("should be 32 bytes");
    let ss_x = sk_e.diffie_hellman(&pk_x.into());

    // Concatenate the ML-KEM-768 ciphertext with the X25519 public key.
    let mut ct = [0u8; 1088 + 32];
    ct[..ct_m.len()].copy_from_slice(&ct_m);
    ct[ct_m.len()..].copy_from_slice(&pk_e);

    // Hash the two shared secrets, the X25519 ephemeral public key, and the X25519 static public
    // key.
    Some((ct, hash(ss_m, ss_x.to_bytes(), &pk_e, &pk_x)))
}

/// Generate a shared key from a decapsulation key and a ciphertext.  If the decapsulation key or
/// the ciphertext are not valid, returns `None`.
pub fn decapsulate(sk: &[u8; 2400 + 32 + 32], c: &[u8; 1088 + 32]) -> Option<[u8; 32]> {
    // Decapsulate the ML-KEM-768 ciphertext.
    let ss_m = crate::decapsulate(
        &sk[..2400].try_into().expect("should be 2400 bytes"),
        &c[..1088].try_into().expect("should be 1088 bytes"),
    )?;

    // Calculate the X25519 ephemeral shared secret.
    let ct_x: [u8; 32] = c[1088..].try_into().expect("should be 32 bytes");
    let sk_x: [u8; 32] = sk[2400..2400 + 32].try_into().expect("should be 32 bytes");
    let ss_x = StaticSecret::from(sk_x).diffie_hellman(&ct_x.into());

    // Hash the two shared secrets, the X25519 ephemeral public key, and the X25519 static public
    // key.
    Some(hash(ss_m, ss_x.to_bytes(), &ct_x, &sk[2400 + 32..]))
}

fn hash(ss_m: [u8; 32], ss_x: [u8; 32], ct_x: &[u8], pk_x: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(br"\.//^\");
    h.update(ss_m);
    h.update(ss_x);
    h.update(ct_x);
    h.update(pk_x);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (ek, dk) = key_gen(&mut rng);
        let (c, k) = encapsulate(&ek, &mut rng).expect("should encapsulate");
        let k_p = decapsulate(&dk, &c).expect("should decapsulate");
        assert_eq!(k, k_p);
    }

    #[test]
    fn test_vector() {
        let d = hex!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        let z = hex!("3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2");
        let x = hex!("35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2");

        let (pk, sk) = key_gen_det(d, z, x);

        assert_eq!(
            sk,
            hex!(
                "
                    24c59d1c7603e7b74bc7aa1bc2cb3a214b3cfaebb63bd85b65408427c498ba394371bb27
                    1f92a3b506b81d54a95a7c0ddfbaa1519553d6f3cd5a601b7db6b0e91a5149468f1f68ad
                    26478bf3c6670e093ac4c49e7a90ba46595de94c50e04129a811a841b39534a87f0ae7b1
                    116553e20c9a566b9b8ff7c7e728b8b201893403a4f252a55230874c256b897834cda349
                    807b25cbd75a30867bfb80328200017f1cb70b56cc546b65d3dc9cdb45107cf10dba3496
                    19043ac35c0b9546309a239039813ed5c40f353a5e8e42193564496112bda56cb38c081d
                    f252ae9c2c7e441a062e92a7c8da7a240c9952d86b5f1bb6a53b38a5ac0a54a84b43f12d
                    a1d0525655684a12090b60b28b0c628db092015547d1070af5d6192e639636615d03c654
                    bb90008ca15b784119f6178a00d7bef4a54a274ac922e55c61a3a8840aa258639484a3bc
                    e2e43b6c969b11275631daa129a61ea0e2939f0877e1a110c8a44b24c54fbb07a958db9f
                    eeca1eb52b086c87bf43a9b02a5b2c4762117c3a99ae4c4e2eaa7a33b9a714737215c103
                    17514f6c4299ef92acd64c4858e85ce737a801890022d7381f3540230c0c8ef50a848a28
                    b09ba0bf8b50619c905751601d7629767449c9c0b2bae321f438a77f412a55e45ecab4b3
                    9053c6561801c639be6495be8fa144ef6029af663407ca9181946de5f3aec7236343ab3b
                    c5a38a09c01b412baf0afb23f9e9b8f2b40810f2ce4ffbcdbfd87972323e98065160bcba
                    34b3afd6c25b664745fca99a9ea75cef019d768485ec23336d9b39e4d05d8d587b30633d
                    4f69ade5753a39680235e44f27995da96798f3a85e184a9fad19320829629f4140417bb7
                    dbf5851ab79258134146d088452774991a087a1c2beaea89f218087ba774ae253b494c27
                    750b1de04b44d953c5e47ab10f65205ee212f9c30391e5299553954916873a0b41164543
                    e801c0b099cb44f48995675823c10b40f4bbac9177a558ca0c30765c2aabfd6a4da54c84
                    13e33902d63f064330f0464982429de2604cd03b4de84a9f821a5470423a40a964dcc418
                    63363d77b02c3127304f942ee71c98c643a427533ef300104948b825277953aaabfd8555
                    88f75a77d199a213ad348116e9e539f6d37068a551c710548b7a2c7ee95f9cd9b3483332
                    673cc44bcb18a778a49455c768e0b340f81102ac6b76b064057151ef101ae143787f5485
                    53558df8035a3ce00c9c43cda43142cca39034b09a7e6089867b4c64980a69ecab2e6818
                    724c35cb909d5d45bc6a349c71b306567664adc0cc8ef698049b4b4b432dd0f69fac0758
                    0f77c4f79b22bb90cb97b341880716853431694c9120f6724ad58d57127fced999ff6229
                    a5d4c3c240129cc812acc73698f949d8e73661f2528262bfccfa5cdf5a2104649806e295
                    ea161217083365aa26cee6ae2f1356e8e1c5cefcc85703447ef1160a1b4a0e8c017b1738
                    02c66c88ab70d39a6c96c1569d5a86245a7eeb087d682219080768745b44bf244f65b567
                    b2658dbae6962ba52b322118e214cfadd7cf3502582dc9cafba952a9637ad36007102597
                    78d99d23f8235da90791604b4f0a4f7640680f59b633d93dfb84282ba54c674b115684a4
                    1bc331b659a61a04883d0c5ebbc0772754a4c33b6a90e52e0678ce06a0453ba8a188b15a
                    496bae6a24177b636d12fbb088f2cd9504ac200231473031a31a5c62e46288fb3edb858b
                    21bc0ea59a212fd1c6dba09e920712d068a2be7abcf4f2a3533443ee1780dd419681a960
                    cd90af5fcaab8c1552ef25572f157a2bbb934a18a5c57a761b54a45d774ac6bc593583a1
                    bcfc4dcd0cca87ab9cff463dc5e80ebbb501d18c8b39e324dbd07ca06cbf75ba33297abc
                    c7aabdd5b308401ba387f533f3927b51e91380f5a59b119e354835ab182db62c76d6d85f
                    a63241743a52012aac281222bc0037e2c493b4777a99cb5929aba155a006bc9b461c365f
                    a3583fac5414b403af9135079b33a10df8819cb462f067253f92b3c45a7fb1c1478d4091
                    e39010ba44071019010daa15c0f43d14641a8fa3a94cfaa2a877ae8113bbf8221ee13223
                    376494fb128b825952d5105ae4157dd6d70f71d5bd48f34d469976629bce6c12931c88ca
                    0882965e27538f272b19796b251226075b131b38564f90159583cd9c4c3c098c8f06a267
                    b262b8731b9e962976c41152a76c30b502d0425635357b43cd3a3ecef5bc9910bb89ca9e
                    91ba75e8121d53c2329b5222df12560d242724523ff60b6ead310d99954d483b91383a72
                    6a937f1b60b474b22ea5b81954580339d81c9f47bab44a3fe0c833a7dba1f5b33a5a2a45
                    9812645c6537c2317163d71b7bd7a4a5459a28a1c28659aad9a1ca9a99a363062d453355
                    108445a673438e77624e73757c1a84d031cf0fb24b1187aafbe6738e9abaf5b42b004b1f
                    a0d96426d3c5324235dd871e7a89364d335ebb6718ad098154208b143b2b43eb9e5fd881
                    6c5225d494b40809b2459903c6486a1db9ac3414945e1867b5869c2f88cf9edc0a216681
                    804578d34923e5a353babba923db907725b384e74e66987292e007e05c6766f267f839b7
                    617c55e28b0fa2121da2d037d6830af9d869e1fb52b0cb645fe221a79b2a46e41980d346
                    71ccc58d8756054b2cca7b13715a05f3925355cca838ab8d2425255f61135727167ad6bc
                    b0632ebf86384b950ad21088c292b4a4fcc0e59c42d3f77fac85cd9f5cb049b3a29505a9
                    84c4c6ac98ca3d0a8f30d2b1bd9815b94b27051b40ffc3455a668b9e141428611b280c1b
                    8f2b55f6eb04e10c68f1340ef1582115f10ee2b785b7ebb0ec3a0c61670cf48107b594cd
                    6e238e0d68961b47983b87879771519d2b7c21681cd494b420f03d004bb06eeb54f9c080
                    c2f2aff6759074d5b3a3b11c73f1af6dc874eeec254d5409fceaa90ff66d90b6930a540f
                    d1d9be1844af1d861ff96a611a414a6c61a78fb2a78e74383ab05ebc73855a818a627242
                    d523a3e2a35ab4285b4a2564f76772aaf8cdc9f87c65f1b4b5819905fb4f9ea59166fbbd
                    b201c5eefc0df7418ca211b5b079a511b8b94429847b537fbed82d57632d63e815d8212d
                    8a280d43328604a6c4d2c1887e7ab061f120a0168db2f4735369b193780f0aeb381ff265
                    3f3b46e206afe77a7e814c7716a1b166727dd2a0b9a7d8aeace425da63977f8103457c9f
                    438a2676c10e3a9c630b855873288ee560ca05c37cc7329e9e502cfac918b9420544445d
                    4cfa93f56ee922c7d660937b5937c3074d62968f006d1211c60296685953e5def3804c2d
                    ad5c36180137c1df12f31385b670fde5cfe76447f6c4b5b50083553c3cb1eea988004b93
                    103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d26016
                    9afa2f75ab916a58d974918835d25e6a435085b2e56f17576740ce2a32fc5145030145cf
                    b97e63e0e41d354274a079d3e6fb2e15
                "
            )
        );

        assert_eq!(
            pk,
            hex!(
                "
                    1bc331b659a61a04883d0c5ebbc0772754a4c33b6a90e52e0678ce06a0453ba8a188b15a
                    496bae6a24177b636d12fbb088f2cd9504ac200231473031a31a5c62e46288fb3edb858b
                    21bc0ea59a212fd1c6dba09e920712d068a2be7abcf4f2a3533443ee1780dd419681a960
                    cd90af5fcaab8c1552ef25572f157a2bbb934a18a5c57a761b54a45d774ac6bc593583a1
                    bcfc4dcd0cca87ab9cff463dc5e80ebbb501d18c8b39e324dbd07ca06cbf75ba33297abc
                    c7aabdd5b308401ba387f533f3927b51e91380f5a59b119e354835ab182db62c76d6d85f
                    a63241743a52012aac281222bc0037e2c493b4777a99cb5929aba155a006bc9b461c365f
                    a3583fac5414b403af9135079b33a10df8819cb462f067253f92b3c45a7fb1c1478d4091
                    e39010ba44071019010daa15c0f43d14641a8fa3a94cfaa2a877ae8113bbf8221ee13223
                    376494fb128b825952d5105ae4157dd6d70f71d5bd48f34d469976629bce6c12931c88ca
                    0882965e27538f272b19796b251226075b131b38564f90159583cd9c4c3c098c8f06a267
                    b262b8731b9e962976c41152a76c30b502d0425635357b43cd3a3ecef5bc9910bb89ca9e
                    91ba75e8121d53c2329b5222df12560d242724523ff60b6ead310d99954d483b91383a72
                    6a937f1b60b474b22ea5b81954580339d81c9f47bab44a3fe0c833a7dba1f5b33a5a2a45
                    9812645c6537c2317163d71b7bd7a4a5459a28a1c28659aad9a1ca9a99a363062d453355
                    108445a673438e77624e73757c1a84d031cf0fb24b1187aafbe6738e9abaf5b42b004b1f
                    a0d96426d3c5324235dd871e7a89364d335ebb6718ad098154208b143b2b43eb9e5fd881
                    6c5225d494b40809b2459903c6486a1db9ac3414945e1867b5869c2f88cf9edc0a216681
                    804578d34923e5a353babba923db907725b384e74e66987292e007e05c6766f267f839b7
                    617c55e28b0fa2121da2d037d6830af9d869e1fb52b0cb645fe221a79b2a46e41980d346
                    71ccc58d8756054b2cca7b13715a05f3925355cca838ab8d2425255f61135727167ad6bc
                    b0632ebf86384b950ad21088c292b4a4fcc0e59c42d3f77fac85cd9f5cb049b3a29505a9
                    84c4c6ac98ca3d0a8f30d2b1bd9815b94b27051b40ffc3455a668b9e141428611b280c1b
                    8f2b55f6eb04e10c68f1340ef1582115f10ee2b785b7ebb0ec3a0c61670cf48107b594cd
                    6e238e0d68961b47983b87879771519d2b7c21681cd494b420f03d004bb06eeb54f9c080
                    c2f2aff6759074d5b3a3b11c73f1af6dc874eeec254d5409fceaa90ff66d90b6930a540f
                    d1d9be1844af1d861ff96a611a414a6c61a78fb2a78e74383ab05ebc73855a818a627242
                    d523a3e2a35ab4285b4a2564f76772aaf8cdc9f87c65f1b4b5819905fb4f9ea59166fbbd
                    b201c5eefc0df7418ca211b5b079a511b8b94429847b537fbed82d57632d63e815d8212d
                    8a280d43328604a6c4d2c1887e7ab061f120a0168db2f4735369b193780f0aeb381ff265
                    3f3b46e206afe77a7e814c7716a1b166727dd2a0b9a7d8aeace425da63977f8103457c9f
                    438a2676c10e3a9c630b855873288ee560ca05c37cc7329e9e502cfac918b9420544445d
                    4cfa93f56ee922c7d660937b5937c3074d62968f006d1211c60296685953e5dee56f1757
                    6740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15
                "
            )
        );

        let m = hex!("badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea");
        let z = hex!("17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef");
        let (ct, ss) = encapsulate_det(&pk, m, z).expect("should encapsulate");

        assert_eq!(
            ct,
            hex!(
                "
                    718ad10318b367fc4390f63147fa5250ef61b65384a563f2c7951b2d45881fcf9f446ddd
                    4443417eed0c001e635a994cda366f118bdd1cf0be0417abd1b615cc669e1b949280e28f
                    52d3d5035c6420ff6c943421ee7589e681828c95942d4f9968f32b9ad30cccff0d98fa84
                    b187164530dc83f9cde75ab1958c22dbff8af921c9ebc678a658b69663f72e7c1632b6ac
                    8ddcbc6c8a06c3316b1aefdd07989ef944fc51406e12db6865344e03f447520d50c93fab
                    1513d80cbc836950e2b52f424bb46155ba4c2e21ec5dff762bf7e92e54e0fb7618e73072
                    607ba03b1de16f109e22dd5832a7eadfeb2ef00244bbaf930106cbcd2ab008f468de6d98
                    632e9e225091a010e361ce751d633e6c37ba2530bca6fbe9d2e5348e4e168e154922992a
                    ef45a265ec649ce21480504b609ad5f1b0b094b74d55aaea60b8f71398cd9340802e9141
                    5937ffaa482c6678f8421c63583e8acd8d00bf285b52a26fa577aed109acd94ef7559554
                    aa378f87283a7ee94af98e21a6fbac8802336ff980e15e498042a8148b69e1d8aab0b712
                    6d0b885f9a57c1ea83efcce8dccfee076dbc2f9c074525ed4e7472c3e09a9f1c50ff5111
                    50159c1be7730686c04e46368e37f2e8c82b8436463445b0edaefab876731497abcc563b
                    1978eac34cf73b5b213549d1f74271d48f6a085155acd8d7db739ce6e70ad25ee636231e
                    4151725d55ea781d483e54850e1ebda401276616e7a62b22efa2e3098a006dfacaa1fca5
                    4ade6a119f3a215b523210164a7f299d2c7b8ad8a637bc1fba56de28ffa800b522246dbe
                    c7148ced56ed292c7d92004065598bc573dd30259d84b6d923d2769ce260cdab0ad17673
                    ef7388c020b8e8bcd055232a7240fe2fa4fcbeadbc46366aa47729f5502dbfee8a623ab8
                    ec6f6020013aeff975f255b597a11eed1335457b9903da42a27a39fdb0edbb11742e4e52
                    1c833b7952d3fd28f428eecb6f78b99ff0a5eb097793f78f1a70612811766fcbe0f9aa3c
                    a4afd8a364f5584333d8a4cdc096a3762ea6cce70dfa42967f5a7c2dbef688b37885fa26
                    220dc800bcb1ae83d35ffca54a6dabba730764d60b1a4a506206efa380d7d1d89069778b
                    082bb92396af4547024797797e01c927c78c9f70750ef2002dfe1516baa4f165a3176942
                    d35d9527f4b33505484130cd573f9d4a1f1e6656aff881aab482fb3d6151ab02f7626703
                    3f3feb9718fbfed05a9b69a8d817a7e4a41efbe3ffeb355d1013778f14d4c30c92a38619
                    0fa23b388feddc635b22d8fa4998b65d483cd3b595553092123e144c49d91ddc2f7a88f3
                    ef1ad2b0b19636bc3f50f61ea5157c73a1a5b956349b6cdf3ff50ec9ef7cbc1137b27d78
                    39276a3ed4e778c505206669686ef038b5808117fedf60ef3598e8ed1db1e5ad64f04af3
                    8e60e82fe04bc75594fd9fcd8bb79237adb9c9ffd3dc2c907345f874aec7055576a32263
                    486120ff62ad690a988919e941d33ed93706f6984032e205084cc46585b5aef035c22ddb
                    b3b0ba04e83f80c1b06b4975f00207b357550d24405189412ea6a83ad56c4873f499fdbd
                    c761aa72
                "
            )
        );
        assert_eq!(ss, hex!("2fae7214767890c4703fad953f5e3f91303111498caa135d77cde634151e71b5"));
    }
}
