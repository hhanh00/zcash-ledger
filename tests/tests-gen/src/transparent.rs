use anyhow::Result;

use rand::RngCore;

use ripemd::{Digest, Ripemd160};
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;

use zcash_primitives::legacy::TransparentAddress;
use zcash_primitives::transaction::components::transparent::builder::{
    TransparentBuilder, Unauthorized,
};
use zcash_primitives::transaction::components::transparent::Bundle;
use zcash_primitives::transaction::components::{Amount, OutPoint, TxOut};

use crate::{ledger_add_t_input, ledger_add_t_output, ledger_set_stage, random256};

pub fn build_transparent_bundle<R: RngCore>(
    sk: &SecretKey,
    recipient_address: &TransparentAddress,
    spends: &[u64],
    outputs: &[u64],
    mut r: R,
) -> Result<Option<Bundle<Unauthorized>>> {
    if spends.is_empty() && outputs.is_empty() {
        ledger_set_stage(2)?;
        ledger_set_stage(3)?;
        return Ok(None);
    }
    let mut builder = TransparentBuilder::empty();
    let secp = Secp256k1::<All>::new();
    let pub_key = PublicKey::from_secret_key(&secp, sk);
    let pub_key = pub_key.serialize();
    let pub_key = Ripemd160::digest(&Sha256::digest(&pub_key));
    let source_address = TransparentAddress::PublicKey(pub_key.into());
    for sp in spends {
        let utxo = OutPoint::new(random256(&mut r), 0);
        let coin = TxOut {
            value: Amount::from_u64(*sp).unwrap(),
            script_pubkey: source_address.clone().script(),
        };
        builder.add_input(sk.clone(), utxo, coin).unwrap();
        ledger_add_t_input(*sp)?;
    }
    ledger_set_stage(2)?;
    for output in outputs {
        builder
            .add_output(
                &recipient_address.clone(),
                Amount::from_u64(*output).unwrap(),
            )
            .unwrap();
        if let TransparentAddress::PublicKey(pkh) = recipient_address {
            ledger_add_t_output(*output, 0, pkh)?;
        }
    }
    ledger_set_stage(3)?;
    let bundle = builder.build().unwrap();
    Ok(Some(bundle))
}
