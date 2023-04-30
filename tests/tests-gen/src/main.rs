use ::orchard::keys::Scope;
use anyhow::Result;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use secp256k1::SecretKey;

use zcash_primitives::consensus::{BlockHeight, BranchId, Network};
use zcash_primitives::legacy::TransparentAddress;
use zcash_primitives::transaction::{TransactionData, TxVersion, Unauthorized};
use zcash_primitives::zip32::ExtendedSpendingKey;

use crate::orchard::build_orchard_bundle;
use crate::sapling::build_sapling_bundle;
use crate::transparent::build_transparent_bundle;
use zcash_proofs::prover::LocalTxProver;

pub mod orchard;
pub mod sapling;
pub mod transparent;

pub fn random256<R: RngCore>(mut r: R) -> [u8; 32] {
    let mut res = [0u8; 32];
    r.fill_bytes(&mut res);
    res
}

pub fn main() -> Result<()> {
    let network: Network = Network::MainNetwork;
    let prover = LocalTxProver::with_default_location().unwrap();
    let mut rng = ChaCha20Rng::from_seed([0; 32]);

    let tsk = SecretKey::from_slice(&[1; 32]).unwrap();
    let transparent_bundle = build_transparent_bundle(
        &tsk,
        &TransparentAddress::PublicKey([3; 20]),
        &[10000, 15000],
        &[14000, 10000],
        &mut rng,
    )
    .unwrap();

    let sk = ExtendedSpendingKey::master(&random256(&mut rng));
    let sk2 = ExtendedSpendingKey::master(&random256(&mut rng));
    let sapling_bundle = build_sapling_bundle(
        network,
        &sk,
        &sk2.default_address().1,
        &[10000, 20000],
        &[25000],
        &prover,
        &mut rng,
    )
    .unwrap();

    let osk = ::orchard::keys::SpendingKey::from_bytes([2; 32]).unwrap();
    let fvk = ::orchard::keys::FullViewingKey::from(&osk);
    let address = fvk.address_at(0u64, Scope::External);
    let orchard_bundle = build_orchard_bundle(&fvk, &address, &[], &[], &mut rng).unwrap();

    let _tx_data = TransactionData::<Unauthorized>::from_parts(
        TxVersion::Zip225,
        BranchId::Nu5,
        0,
        BlockHeight::from_u32(2_000_000),
        transparent_bundle,
        None,
        sapling_bundle,
        orchard_bundle,
    );

    Ok(())
}
