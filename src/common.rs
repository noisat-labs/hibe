use rand::{ Rng, Rand };
use sha3::{ Shake256, Sha3XofReader };
use digest::{ Input, ExtendableOutput, XofReader };
use byteorder::{ ByteOrder, LittleEndian };
use pairing::{ CurveProjective, PrimeField };
use pairing::bls12_381::{ Fr, G1, G2 };
use super::Mpk;


struct HashRng(Sha3XofReader);

impl HashRng {
    fn new<A: AsRef<[u8]>>(value: A) -> HashRng {
        let mut hasher = Shake256::default();
        hasher.process(value.as_ref());
        HashRng(hasher.xof_result())
    }
}

impl Rng for HashRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        LittleEndian::read_u32(&bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        LittleEndian::read_u64(&bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest)
    }
}


impl Mpk {
    /// F(j, id) = g1^id * h_j
    pub fn f(&self, j: usize, id: &str) -> (G1, G2) {
        let Mpk { g1: (g1_1, g1_2), h, .. } = self;

        let mut idrng = HashRng::new(id);
        let id = Fr::rand(&mut idrng);

        let mut result_1 = g1_1.clone();
        result_1.mul_assign(id.into_repr());
        result_1.add_assign(&h[j].0);

        let mut result_2 = g1_2.clone();
        result_2.mul_assign(id.into_repr());
        result_2.add_assign(&h[j].1);

        (result_1, result_2)
    }
}
