use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic, Seed};
use blake2b_simd::Params;
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use tiny_hderive::bip32::ExtendedPrivKey;
use zcash_client_backend::encoding::encode_payment_address;
use zcash_primitives::consensus::{MainNetwork, Parameters};
use zcash_primitives::sapling::keys::{ExpandedSpendingKey, FullViewingKey};
use zcash_primitives::zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey};
use zcash_primitives::zip32::sapling::DiversifierKey;

pub const DEFAULT_SEED: &str = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin";

#[test]
pub fn derive_address() -> Result<()> {
    let mnemonic = Mnemonic::from_phrase(DEFAULT_SEED, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    let ext = ExtendedPrivKey::derive(seed.as_bytes(), "m/44'/133'/0'/0/0")
        .map_err(|_| anyhow!("Invalid derivation path"))?;
    let secret_key = SecretKey::from_slice(&ext.secret())?;
    let secp = Secp256k1::<All>::new();
    let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
    let pub_key = pub_key.serialize();
    println!("pubkey {}", hex::encode(&pub_key));

    let master = ext.secret();
    let mut seed = Params::new().hash_length(32).personal(b"ZSaplingSeedHash").to_state();
    seed.update(&master);
    let seed = seed.finalize();
    println!("sk {}", hex::encode(seed.as_bytes()));

    let expsk = ExpandedSpendingKey::from_spending_key(seed.as_bytes());
    let fvk = FullViewingKey::from_expanded_spending_key(&expsk);
    let dk = DiversifierKey::master(seed.as_bytes());
    println!("dfvk {}{}", hex::encode(fvk.to_bytes()), hex::encode(&dk.as_bytes()));

    let mut seed = Params::new().hash_length(32).personal(b"ZOrchardSeedHash").to_state();
    seed.update(&master);
    let seed = seed.finalize();
    let sk = orchard::keys::SpendingKey::from_bytes(seed.as_bytes().try_into().unwrap()).unwrap();
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    println!("fvk {}", hex::encode(fvk.to_bytes()));

    Ok(())

}
