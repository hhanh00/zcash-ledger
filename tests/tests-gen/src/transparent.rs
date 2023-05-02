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

use crate::{random256, TestWriter};

pub fn build_transparent_bundle<R: RngCore>(
    sk: &SecretKey,
    recipient_address: &TransparentAddress,
    spends: &[u64],
    outputs: &[u64],
    test_writer: &mut TestWriter,
    mut r: R,
) -> Result<Option<Bundle<Unauthorized>>> {
    if spends.is_empty() && outputs.is_empty() {
        test_writer.ledger_set_stage(2)?;
        test_writer.ledger_set_stage(3)?;
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
        test_writer.ledger_add_t_input(*sp)?;
    }
    test_writer.ledger_set_stage(2)?;
    for output in outputs {
        builder
            .add_output(
                &recipient_address.clone(),
                Amount::from_u64(*output).unwrap(),
            )
            .unwrap();
        if let TransparentAddress::PublicKey(pkh) = recipient_address {
            test_writer.ledger_add_t_output(*output, 0, pkh)?;
        }
    }
    test_writer.ledger_set_stage(3)?;
    let bundle = builder.build().unwrap();
    Ok(Some(bundle))
}
