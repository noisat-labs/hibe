//! BB-HIBE scheme 1
//! [Efficient Selective-ID Secure Identity Based Encryption Without Random Oracles](https://eprint.iacr.org/2004/172.pdf)

extern crate rand;
extern crate sha3;
extern crate digest;
extern crate byteorder;
extern crate pairing;

mod common;

use rand::{ Rng, Rand };
use pairing::{ Engine, Field, CurveProjective, CurveAffine, PrimeField };
use pairing::bls12_381::{ Bls12, Fr, G1, G2, Fq12 };


pub const L: usize = 2;

pub type Gt = Fq12;

pub struct Msk(G2);

pub struct Mpk {
    g: (G1, G2),
    g1: (G1, G2),
    g2: G2,
    h: [(G1, G2); L]
}

pub struct Sk(G2, Vec<G2>);
pub struct Ct(Gt, G1, Vec<G1>);

pub fn setup<R: Rng>(rng: &mut R) -> (Msk, Mpk) {
    let a = Fr::rand(rng);

    // g <- G
    let g_1 = G1::rand(rng);
    let g_2 = G2::rand(rng);

    let g_1_affine = g_1.into_affine();
    let g_2_affine = g_2.into_affine();

    // g1 = g^a
    let g1_1 = g_1_affine.mul(a.into_repr());
    let g1_2 = g_2_affine.mul(a.into_repr());

    // g2 <- G
    let r = Fr::rand(rng);
    let g2 = g_2_affine.mul(r.into_repr());

    // h <- G
    let mut hs = [(G1::zero(), G2::zero()); L];
    for i in 0..L {
        let r = Fr::rand(rng);
        let h_1 = g_1_affine.mul(r.into_repr());
        let h_2 = g_2_affine.mul(r.into_repr());
        hs[i] = (h_1, h_2);
    }

    // msk = g2^a
    let msk_2 = g2.into_affine().mul(a.into_repr());

    (
        Msk(msk_2),
        Mpk {
            g: (g_1, g_2),
            g1: (g1_1, g1_2),
            g2: g2,
            h: hs
        }
    )
}

pub fn keygen<R: Rng>(rng: &mut R, mpk: &Mpk, Msk(msk): &Msk, ids: &[&str]) -> Sk {
    let Mpk { g: (_, g), .. } = mpk;

    assert!(ids.len() <= L);

    let mut d0 = msk.clone();
    let mut dn = Vec::new();

    for i in 0..ids.len() {
        let r = Fr::rand(rng);

        // MSK * prod_(k=1)^j F(id_k)^(r_k)
        let (_, mut t) = mpk.f(i, &ids[i]);
        t.mul_assign(r.into_repr());
        d0.add_assign(&t);

        // g^(r_j)
        let t1 = g.into_affine().mul(r.into_repr());
        dn.push(t1);
    }

    Sk(d0, dn)
}

impl Sk {
    pub fn keygen<R: Rng>(&self, rng: &mut R, mpk: &Mpk, ids: &[&str]) -> Sk {
        let Sk(d0, dn) = self;
        let Mpk { g: (_, g), .. } = mpk;

        assert!(dn.len() + ids.len() <= L);

        let len = dn.len();
        let mut d0 = d0.clone();
        let mut dn = dn.clone();

        for i in 0..ids.len() {
            let r = Fr::rand(rng);

            // d0 * F(id_j)^(r_j)
            let (_, mut t) = mpk.f(len + i, &ids[i]);
            t.mul_assign(r.into_repr());
            d0.add_assign(&t);

            // g^(r_j)
            let t1 = g.into_affine().mul(r.into_repr());
            dn.push(t1);
        }

        Sk(d0, dn)
    }
}

pub fn enc<R: Rng>(rng: &mut R, mpk: &Mpk, ids: &[&str], msg: &Gt) -> Ct {
    let Mpk { g: (g, _), g1: (g1, _), g2, .. } = mpk;
    let s = Fr::rand(rng);

    assert!(ids.len() <= L);

    // M * e(g1^s, g2)
    let mut c1 = Bls12::pairing(g1.into_affine().mul(s.into_repr()), g2.into_affine());
    c1.mul_assign(msg);

    // g^s
    let c2 = g.into_affine().mul(s.into_repr());

    let mut c3 = Vec::new();
    for i in 0..ids.len() {
        // F(id)^s
        let (mut t, _) = mpk.f(i, &ids[i]);
        t.mul_assign(s.into_repr());
        c3.push(t);
    }

    Ct(c1, c2, c3)
}

pub fn dec(sk: &Sk, ct: &Ct) -> Gt {
    let Sk(d0, dn) = sk;
    let Ct(aa, bb, cc) = ct;

    assert_eq!(dn.len(), cc.len());

    // A * K / e(B, d0)
    let mut result = aa.clone();

    // K = prod_(k=1)^j e(C_k, d_k)
    for i in 0..cc.len() {
        let t = Bls12::pairing(cc[i].into_affine(), dn[i].into_affine());
        result.mul_assign(&t);
    }

    let t2 = Bls12::pairing(bb.into_affine(), d0.into_affine());
    result.mul_assign(&t2.inverse().unwrap());

    result
}


#[test]
fn test_hibe() {
    use rand::thread_rng;

    let mut rng = thread_rng();

    let (msk, mpk) = setup(&mut rng);
    let sk = keygen(&mut rng, &mpk, &msk, &["pkg@ibe.rs", "alice@ibe.rs"]);
    let m = Gt::rand(&mut rng);
    let ct = enc(&mut rng, &mpk, &["pkg@ibe.rs", "alice@ibe.rs"], &m);
    let m2 = dec(&sk, &ct);
    assert_eq!(m, m2);

    let sk = keygen(&mut rng, &mpk, &msk, &["pkg@ibe.rs", "bob@ibe.rs"]);
    let m3 = dec(&sk, &ct);
    assert_ne!(m3, m2);

    let pkg_sk = keygen(&mut rng, &mpk, &msk, &["pkg@ibe.rs"]);
    let sk = pkg_sk.keygen(&mut rng, &mpk, &["alice@ibe.rs"]);
    let m2 = dec(&sk, &ct);
    assert_eq!(m, m2);
}
