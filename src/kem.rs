use kem::generic_array::typenum::{UInt, UTerm, B0, B1, U32};
use kem::generic_array::GenericArray;
use kem::{Decapsulator, EncappedKey, Encapsulator};
use rand_core::{CryptoRng, RngCore};

#[rustfmt::skip]
pub type U1088 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B1>, B0>, B0>, B0>, B0>, B0>, B0>;

#[derive(Debug)]
pub struct EncapsulatingKey {
    ek: [u8; 1184],
}

#[derive(Debug)]
pub struct DecapsulatingKey {
    dk: [u8; 2400],
}

impl Decapsulator<EncapsulatedKey> for DecapsulatingKey {
    fn try_decap(
        &self,
        encapped_key: &EncapsulatedKey,
    ) -> Result<kem::SharedSecret<EncapsulatedKey>, kem::Error> {
        crate::decapsulate(&self.dk, &encapped_key.ciphertext)
            .map(|ss| kem::SharedSecret::new(ss.into()))
            .ok_or(kem::Error)
    }
}

#[derive(Debug)]
pub struct MlKem768;

impl MlKem768 {
    pub fn key_gen(rng: impl RngCore + CryptoRng) -> (EncapsulatingKey, DecapsulatingKey) {
        let (ek, dk) = crate::key_gen(rng);
        (EncapsulatingKey { ek }, DecapsulatingKey { dk })
    }
}

impl Encapsulator<EncapsulatedKey> for MlKem768 {
    fn try_encap<R: rand_core::CryptoRng + rand_core::RngCore>(
        &self,
        csprng: &mut R,
        recip_pubkey: &<EncapsulatedKey as EncappedKey>::RecipientPublicKey,
    ) -> Result<(EncapsulatedKey, kem::SharedSecret<EncapsulatedKey>), kem::Error> {
        let mut ek = [0u8; 1184];
        ek.copy_from_slice(&recip_pubkey.ek);
        crate::encapsulate(&ek, csprng)
            .map(|(ct, ss)| (EncapsulatedKey { ciphertext: ct }, kem::SharedSecret::new(ss.into())))
            .ok_or(kem::Error)
    }
}

#[derive(Debug)]
pub struct EncapsulatedKey {
    ciphertext: [u8; 1088],
}

impl AsRef<[u8]> for EncapsulatedKey {
    fn as_ref(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl EncappedKey for EncapsulatedKey {
    type EncappedKeySize = U1088;

    type SharedSecretSize = U32;

    type SenderPublicKey = EncapsulatingKey;

    type RecipientPublicKey = EncapsulatingKey;

    fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, kem::Error> {
        let mut key = EncapsulatedKey { ciphertext: [0u8; 1088] };
        key.ciphertext.copy_from_slice(bytes);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use kem::generic_array::typenum::{U1024, U64};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn u1088() {
        let x = U1024::new() + U64::new();
        let _: U1088 = x;
    }

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (ek, dk) = MlKem768::key_gen(&mut rng);
        let (ct, k) = MlKem768.try_encap(&mut rng, &ek).expect("should encapsulate");
        let k_p = dk.try_decap(&ct).expect("should decapsulate");
        assert_eq!(k.as_bytes(), k_p.as_bytes());
    }
}
