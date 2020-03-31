use rand::{RngCore, SeedableRng};
use std::collections::HashMap;

pub const INTERVALS_PER_LIFETIME: usize = 4 * 24 * 14;
pub const CEN_BYTES: usize = 16;
pub type CEN = [u8; CEN_BYTES];
pub type PK = [u8; 32];

pub fn calculate_cens_hashing(key: PK) -> [CEN; INTERVALS_PER_LIFETIME] {
    let mut out = [[0u8; CEN_BYTES]; INTERVALS_PER_LIFETIME];

    let mut hasher = blake3::Hasher::new_keyed(&key);

    for i in 0..INTERVALS_PER_LIFETIME {
        hasher.reset();
        hasher.update(&u64::to_le_bytes(i as u64));
        hasher.finalize_xof().fill(&mut out[i]);
    }

    out
}

pub fn calculate_cens_hashing_batch(key: PK) -> [CEN; INTERVALS_PER_LIFETIME] {
    let mut out = [[0u8; CEN_BYTES]; INTERVALS_PER_LIFETIME];

    let mut hash = blake3::Hasher::new_keyed(&key).finalize_xof();

    for i in 0..INTERVALS_PER_LIFETIME {
        hash.fill(&mut out[i]);
    }

    out
}

pub fn calculate_cens_chacha8(key: PK) -> [CEN; INTERVALS_PER_LIFETIME] {
    let mut out = [[0u8; CEN_BYTES]; INTERVALS_PER_LIFETIME];

    let mut rng = rand_chacha::ChaCha8Rng::from_seed(key);

    for i in 0..INTERVALS_PER_LIFETIME {
        rng.fill_bytes(&mut out[i]);
    }

    out
}

pub struct HashHasher([u8; 8]);
impl std::hash::Hasher for HashHasher {
    fn write(&mut self, value: &[u8]) {
        self.0.copy_from_slice(&value[..8]);
    }

    fn finish(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

#[derive(Default)]
pub struct HashHasherBuilder;

impl std::hash::BuildHasher for HashHasherBuilder {
    type Hasher = HashHasher;
    fn build_hasher(&self) -> HashHasher {
        HashHasher([0u8; 8])
    }
}

pub fn check_cen_membership<F: FnOnce(PK) -> [CEN; INTERVALS_PER_LIFETIME]>(
    log: &HashMap<CEN, i64, HashHasherBuilder>,
    pk: PK,
    gen_cens: F,
) -> Option<i64> {
    let cens = gen_cens(pk);
    cens.iter().filter_map(|c| log.get(c)).map(|c| *c).max()
}

pub fn check_cen_manu(log: &[(CEN, i64)], pk: PK) -> Option<i64> {
    use aes_soft::Aes128;
    use block_cipher_trait::BlockCipher;
    use generic_array::GenericArray;

    let cipher = Aes128::new_varkey(&pk[..16]).unwrap();

    log.into_iter()
        .filter_map(move |(cen, ts)| {
            let mut block = GenericArray::clone_from_slice(cen);
            cipher.decrypt_block(&mut block);
            if block.into_iter().take(8).all(|u| u == 0) {
                Some(ts)
            } else {
                None
            }
        })
        .map(|c| *c)
        .max()
}

pub fn check_cen_manu_ni(log: &[(CEN, i64)], pk: PK) -> Option<i64> {
    use aesni::Aes128;
    use block_cipher_trait::BlockCipher;
    use generic_array::GenericArray;

    let cipher = Aes128::new_varkey(&pk[..16]).unwrap();

    log.into_iter()
        .filter_map(move |(cen, ts)| {
            let mut block = GenericArray::clone_from_slice(cen);
            cipher.decrypt_block(&mut block);
            if block.into_iter().take(8).all(|u| u == 0) {
                Some(ts)
            } else {
                None
            }
        })
        .map(|c| *c)
        .max()
}
