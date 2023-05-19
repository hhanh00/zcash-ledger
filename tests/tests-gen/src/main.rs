use std::fmt::{Display, Formatter};
use ::orchard::keys::{Scope};
use anyhow::{Result};
use blake2b_simd::{Hash, Params};
use byteorder::{WriteBytesExt, LE};
use std::io::{stdout, Write};
use std::path::Path;
use hex_literal::hex;
use jubjub::Fr;
use pasta_curves::group::GroupEncoding;

use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use secp256k1::SecretKey;

use zcash_primitives::consensus::{BlockHeight, BranchId};
use zcash_primitives::constants::SPENDING_KEY_GENERATOR;

use zcash_primitives::legacy::TransparentAddress;
use zcash_primitives::sapling::keys::PreparedIncomingViewingKey;
use zcash_primitives::sapling::redjubjub::{PublicKey, Signature};

use zcash_primitives::sapling::SaplingIvk;

use zcash_primitives::transaction::sighash::{SignableInput, TransparentAuthorizingContext};
use zcash_primitives::transaction::sighash_v5::v5_signature_hash;
use zcash_primitives::transaction::txid::{TxIdDigester};
use zcash_primitives::transaction::{TransactionData, TxVersion, Unauthorized};
use zcash_primitives::zip32::{ExtendedSpendingKey};

use crate::orchard::build_orchard_bundle;
use crate::sapling::build_sapling_bundle;
use crate::transparent::build_transparent_bundle;
use crate::transport::TestWriter;

pub mod orchard;
pub mod sapling;
pub mod transparent;
pub mod transport;
pub mod key;

pub fn random256<R: RngCore>(mut r: R) -> [u8; 32] {
    let mut res = [0u8; 32];
    r.fill_bytes(&mut res);
    res
}

#[derive(Debug)]
pub struct TxConfig {
    t_ins: u32,
    t_outs: u32,
    s_ins: u32,
    s_outs: u32,
    o_ins: u32,
    o_outs: u32,
}

impl Display for TxConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.t_ins != 0 { write!(f, "t")?; }
        if self.s_ins != 0 { write!(f, "z")?; }
        if self.o_ins != 0 { write!(f, "o")?; }
        write!(f, "2")?;
        if self.t_outs != 0 { write!(f, "t")?; }
        if self.s_outs != 0 { write!(f, "z")?; }
        if self.o_outs != 0 { write!(f, "o")?; }
        Ok(())
    }
}

fn generate_amounts(c: u32, base: u32) -> Vec<u64> {
    if c == 0 {
        return vec![];
    }
    vec![base as u64; c as usize]
}

pub fn test_all_tx_types() -> Result<()> {
    let mut test_writer = TestWriter::new(Path::new("test.json"));

    for i in 1..8 {
        for j in 0..8 {
            let config = TxConfig {
                t_ins: i & 1,
                t_outs: j & 1,
                s_ins: (i & 2) >> 1,
                s_outs: (j & 2) >> 1,
                o_ins: (i & 4) >> 2,
                o_outs: (j & 4) >> 2,
            };

            println!("{:?}", config);

            assert!(test_sighash(&config.to_string(), config, &mut test_writer, OsRng)?);
        }
    }

    test_writer.close();
    Ok(())
}

pub fn test_z2z_in_depth() -> Result<()> {
    let mut test_writer = TestWriter::new(Path::new("test-z2z.json"));
    for _ in 0..10 {
        for i in 1..3 {
            for j in 0..3 {
                let config = TxConfig {
                    t_ins: 0,
                    t_outs: 0,
                    s_ins: i,
                    s_outs: j,
                    o_ins: 0,
                    o_outs: 0,
                };

                println!("{:?}", config);

                assert!(test_sighash(&config.to_string(), config, &mut test_writer, OsRng)?);
            }
        }
    }
    test_writer.close();

    Ok(())
}

pub fn test_sapling_sign() -> Result<()> {
    let mut test_writer = TestWriter::new(Path::new("sapling_sign.json"));
    test_writer.ledger_init()?;
    let pgk = test_writer.ledger_get_proofgen_key()?;
    let mut rng = ChaCha20Rng::from_seed([0; 32]);

    // Run test 100 times
    for i in 0..100 {
        print!("\rRun {}", i);
        stdout().flush()?;
        // random alpha
        let mut alpha = [0u8; 64];
        rng.fill_bytes(&mut alpha);
        let ar = Fr::from_bytes_wide(&alpha);
        let rk = PublicKey(pgk.ak.clone().into()).randomize(ar, SPENDING_KEY_GENERATOR);

        // random sig_hash
        let mut sig_hash = [0u8; 32];
        rng.fill_bytes(&mut sig_hash);

        // sign
        let signature = test_writer.ledger_sapling_sign(&alpha, &sig_hash)?;

        // verify
        let signature = Signature::read(&*signature)?;
        let mut message = vec![];
        message.write_all(&rk.0.to_bytes())?;
        message.write_all(sig_hash.as_ref())?;
        let verified = rk.verify_with_zip216(&message, &signature, SPENDING_KEY_GENERATOR, true);
        if !verified {
            anyhow::bail!("Invalid Sapling signature");
        }
    }

    Ok(())
}

pub fn test_raw_sign() -> Result<()> {
    let mut test_writer = TestWriter::new(Path::new("raw.json"));
    test_writer.ledger_init()?;
    for _ in 0..100 {
        let res = test_writer.apdu(&hex!("e0800000601320a058d7b3566bd520daaa3ed2bf0ac5b8b120fb852773c3639734b45c91a42dd4cb83f8840d2eedb158131062ac3f1f2cf8ff6dcd1856e86a1e6c3167167ee5a688742b47c5adfb59d4df76fd1db1e51ee03b1ca9f82aca173edb8b729347"))?;
        println!("{}", hex::encode(&res));
        assert_eq!(res, hex!("2c14c682123f6e2e02c78b283e0d58f01fbc7c97910df48f1633beb4efb19440c37e021e5fff51b763026af1d8c7c399a53af117009d30278c640f3e8d617c0a"));
    }

    Ok(())
}

pub fn main() -> Result<()> {
    // test_all_tx_types()?;
    // test_z2z_in_depth()?;
    test_sapling_sign()?;
    // test_raw_sign()?;

    Ok(())
}

const BASE_AMOUNT: u32 = 1000;

pub fn test_sighash<R: RngCore>(name: &str, config: TxConfig, test_writer: &mut TestWriter, mut rng: R) -> Result<bool> {
    test_writer.ledger_init_tx(name)?;
    println!("Test {}", name);

    let tsk = SecretKey::from_slice(&[1; 32]).unwrap();
    let transparent_bundle = build_transparent_bundle(
        &tsk,
        &TransparentAddress::PublicKey([0; 20]),
        &generate_amounts(config.t_ins, BASE_AMOUNT),
        &generate_amounts(config.t_outs, BASE_AMOUNT),
        test_writer,
        &mut rng,
    )
    .unwrap();

    let sk = ExtendedSpendingKey::master(&random256(&mut rng));
    let (_di, recipient_address) = sk.default_address();
    let ivk = sk.to_diversifiable_full_viewing_key().fvk().vk.ivk();
    let sapling_bundle = build_sapling_bundle(
        &sk,
        &recipient_address,
        &generate_amounts(config.s_ins, BASE_AMOUNT),
        &generate_amounts(config.s_outs, BASE_AMOUNT),
        test_writer,
        &mut rng,
    )
    .unwrap();

    let osk = ::orchard::keys::SpendingKey::from_bytes([2; 32]).unwrap();
    let fvk = ::orchard::keys::FullViewingKey::from(&osk);

    let address = fvk.address_at(0u64, Scope::External);
    let orchard_bundle = build_orchard_bundle(
        &fvk,
        &address,
        &generate_amounts(config.o_ins, BASE_AMOUNT),
        &generate_amounts(config.o_outs, BASE_AMOUNT),
        test_writer,
        &mut rng,
    )
    .unwrap();

    let tx_data = TransactionData::<Unauthorized>::from_parts(
        TxVersion::Zip225,
        BranchId::Nu5,
        0,
        BlockHeight::from_u32(2_000_000),
        transparent_bundle,
        None,
        sapling_bundle,
        orchard_bundle,
    );

    let txid_parts = tx_data.digest(TxIdDigester);
    println!("TxId parts {:?}", txid_parts);
    let sig_hash = v5_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts);
    let mut ok = sighash(ivk.clone(), &tx_data, None, test_writer)? == sig_hash;
    println!("Shielded sighash {:?}", sig_hash);

    let n_txin = tx_data
        .transparent_bundle()
        .map(|b| b.vin.len())
        .unwrap_or(0);
    for i in 0..n_txin {
        let bundle = tx_data.transparent_bundle().unwrap();
        let amount = bundle.authorization.input_amounts()[i];
        let script = &bundle.authorization.input_scriptpubkeys()[i];
        let sig_hash = v5_signature_hash(
            &tx_data,
            &SignableInput::Transparent {
                hash_type: 1,
                index: i,
                script_code: script,
                script_pubkey: script,
                value: amount,
            },
            &txid_parts,
        );
        // Check that the sig hash we calculate matches the sig hash calculated by the
        // official crate
        let eq =
            sighash(ivk.clone(), &tx_data, Some(i as u32), test_writer)? ==
            sig_hash;
        if !eq { ok = false; }
    }
    test_writer.ledger_end_tx()?;
    Ok(ok)
}

pub fn sighash(
    ivk: SaplingIvk,
    tx_data: &TransactionData<Unauthorized>,
    index: Option<u32>,
    test_writer: &mut TestWriter
) -> Result<Hash> {
    let mut h_header = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdHeadersHash")
        .to_state();
    h_header.write_u32::<LE>(tx_data.version().header())?;
    h_header.write_u32::<LE>(tx_data.version().version_group_id())?;
    h_header.write_u32::<LE>(tx_data.consensus_branch_id().into())?;
    h_header.write_u32::<LE>(tx_data.lock_time())?;
    h_header.write_u32::<LE>(tx_data.expiry_height().into())?;
    let h_header = h_header.finalize();
    println!("Header {:?}", h_header);
    if index.is_none() {
        test_writer.ledger_set_header_digest(h_header.as_bytes())?;
    }

    let mut txin_digest = None;
    let transparent_bundle = tx_data.transparent_bundle();
    let mut h_transparent = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdTranspaHash")
        .to_state();
    if let Some(transparent_bundle) = transparent_bundle {
        let mut h_prevouts = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdPrevoutHash")
            .to_state();
        let mut h_sequences = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdSequencHash")
            .to_state();
        for vin in transparent_bundle.vin.iter() {
            h_prevouts.write_all(vin.prevout.hash())?;
            h_prevouts.write_u32::<LE>(vin.prevout.n())?;
            h_sequences.write_u32::<LE>(vin.sequence)?;
        }
        let mut h_amounts = Params::new()
            .hash_length(32)
            .personal(b"ZTxTrAmountsHash")
            .to_state();
        for amount in transparent_bundle.authorization.input_amounts().iter() {
            h_amounts.write_all(&amount.to_i64_le_bytes())?;
        }
        let mut h_script_pubkeys = Params::new()
            .hash_length(32)
            .personal(b"ZTxTrScriptsHash")
            .to_state();
        for script_pubkey in transparent_bundle
            .authorization
            .input_scriptpubkeys()
            .iter()
        {
            script_pubkey.write(&mut h_script_pubkeys)?;
        }
        let mut h_outputs = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdOutputsHash")
            .to_state();
        for vout in transparent_bundle.vout.iter() {
            h_outputs.write_u64::<LE>(vout.value.into())?;
            vout.script_pubkey.write(&mut h_outputs)?;
        }
        let mut h_txin = Params::new()
            .hash_length(32)
            .personal(b"Zcash___TxInHash")
            .to_state();
        match index {
            Some(index) => {
                let vin = &transparent_bundle.vin[index as usize];
                h_txin.write_all(vin.prevout.hash())?;
                h_txin.write_u32::<LE>(vin.prevout.n())?;
                h_txin.write_all(
                    &transparent_bundle.authorization.input_amounts()[index as usize]
                        .to_i64_le_bytes(),
                )?;
                transparent_bundle.authorization.input_scriptpubkeys()[index as usize]
                    .write(&mut h_txin)?;
                h_txin.write_u32::<LE>(vin.sequence)?;
            }
            None => {}
        }

        let h_prevouts = h_prevouts.finalize();
        let h_amounts = h_amounts.finalize();
        let h_script_pubkeys = h_script_pubkeys.finalize();
        let h_sequences = h_sequences.finalize();
        let h_outputs = h_outputs.finalize();
        let h_txin = h_txin.finalize();
        txin_digest = Some(h_txin);
        println!("PO/S/O {:?} {:?} {:?}", h_prevouts, h_sequences, h_outputs);

        let has_tins = !transparent_bundle.vin.is_empty();
        if has_tins {
            h_transparent.write_u8(1)?;
        }
        h_transparent.write_all(h_prevouts.as_bytes())?;
        if has_tins {
            h_transparent.write_all(h_amounts.as_bytes())?;
            h_transparent.write_all(h_script_pubkeys.as_bytes())?;
        }
        h_transparent.write_all(h_sequences.as_bytes())?;
        h_transparent.write_all(h_outputs.as_bytes())?;
        if has_tins {
            h_transparent.write_all(h_txin.as_bytes())?;
        }
        if index.is_none() {
            test_writer.ledger_set_transparent_merkle_proof(h_prevouts.as_bytes(),
                                                            h_script_pubkeys.as_bytes(), h_sequences.as_bytes())?;
        }
    }
    let h_transparent = h_transparent.finalize();
    println!("Transparent {:?}", h_transparent);

    let sapling_bundle = tx_data.sapling_bundle();
    let mut h_sapling = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdSaplingHash")
        .to_state();
    if let Some(sapling_bundle) = sapling_bundle {
        let mut h_spc = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdSSpendCHash")
            .to_state();
        let mut h_spn = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdSSpendNHash")
            .to_state();
        for sp in sapling_bundle.shielded_spends() {
            h_spc.write_all(&sp.nullifier().0)?;
            h_spn.write_all(&sp.cv().to_bytes())?;
            h_spn.write_all(&sp.anchor().to_bytes())?;
            sp.rk().write(&mut h_spn)?;
        }
        let h_spc = h_spc.finalize();
        let h_spn = h_spn.finalize();
        let mut h_spend = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdSSpendsHash")
            .to_state();
        if !sapling_bundle.shielded_spends().is_empty() {
            h_spend.write_all(h_spc.as_bytes())?;
            h_spend.write_all(h_spn.as_bytes())?;
        }
        let h_spend = h_spend.finalize();
        let mut h_oc = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdSOutC__Hash")
            .to_state();
        let mut h_om = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdSOutM__Hash")
            .to_state();
        let mut h_on = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdSOutN__Hash")
            .to_state();
        let _pivk = PreparedIncomingViewingKey::new(&ivk);
        for out in sapling_bundle.shielded_outputs() {
            h_oc.write_all(&out.cmu().to_bytes())?;
            h_oc.write_all(&out.ephemeral_key().0)?;
            h_oc.write_all(&out.enc_ciphertext()[0..52])?;
            h_om.write_all(&out.enc_ciphertext()[52..564])?;
            h_on.write_all(&out.cv().to_bytes())?;
            h_on.write_all(&out.enc_ciphertext()[564..])?;
            h_on.write_all(out.out_ciphertext())?;
        }
        let h_oc = h_oc.finalize();
        let h_om = h_om.finalize();
        let h_on = h_on.finalize();
        let mut h_output = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdSOutputHash")
            .to_state();
        if !sapling_bundle.shielded_outputs().is_empty() {
            h_output.write_all(h_oc.as_bytes())?;
            h_output.write_all(h_om.as_bytes())?;
            h_output.write_all(h_on.as_bytes())?;
        }
        let h_output = h_output.finalize();
        h_sapling.write_all(h_spend.as_bytes())?;
        h_sapling.write_all(h_output.as_bytes())?;
        h_sapling.write_i64::<LE>(sapling_bundle.value_balance().into())?;
        if index.is_none() {
            test_writer.ledger_set_sapling_merkle_proof(h_spend.as_bytes(), h_om.as_bytes(), h_on.as_bytes())?;
        }
    }
    let h_sapling = h_sapling.finalize();
    println!("Sapling {:?}", h_sapling);

    let orchard_bundle = tx_data.orchard_bundle();
    let mut h_orchard = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdOrchardHash")
        .to_state();
    if let Some(orchard_bundle) = orchard_bundle {
        let mut h_ac = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdOrcActCHash")
            .to_state();
        let mut h_am = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdOrcActMHash")
            .to_state();
        let mut h_an = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdOrcActNHash")
            .to_state();
        for action in orchard_bundle.actions() {
            println!("CMX {:?}", action.cmx());
            h_ac.write_all(&action.nullifier().to_bytes())?;
            h_ac.write_all(&action.cmx().to_bytes())?;
            h_ac.write_all(&action.encrypted_note().epk_bytes)?;
            h_ac.write_all(&action.encrypted_note().enc_ciphertext[0..52])?;
            h_am.write_all(&action.encrypted_note().enc_ciphertext[52..564])?;
            h_an.write_all(&action.cv_net().to_bytes())?;
            h_an.write_all(&<[u8; 32]>::from(action.rk()))?;
            h_an.write_all(&action.encrypted_note().enc_ciphertext[564..])?;
            h_an.write_all(&action.encrypted_note().out_ciphertext)?;
        }
        let h_ac = h_ac.finalize();
        let h_am = h_am.finalize();
        let h_an = h_an.finalize();
        h_orchard.write_all(h_ac.as_bytes())?;
        h_orchard.write_all(h_am.as_bytes())?;
        h_orchard.write_all(h_an.as_bytes())?;
        h_orchard.write_u8(orchard_bundle.flags().to_byte())?;
        h_orchard.write_i64::<LE>(orchard_bundle.value_balance().into())?;
        h_orchard.write_all(&orchard_bundle.anchor().to_bytes())?;
        if index.is_none() {
            test_writer.ledger_set_orchard_merkle_proof(&orchard_bundle.anchor().to_bytes(),
                                                        h_am.as_bytes(), h_an.as_bytes())?;
        }
    }
    let h_orchard = h_orchard.finalize();
    println!("Orchard {:?}", h_orchard);

    let branch_id: u32 = tx_data.consensus_branch_id().into();
    let perso = [
        b"ZcashTxHash_".as_slice(),
        &branch_id.to_le_bytes().as_slice(),
    ]
    .concat();

    let mut h_sighash = Params::new().hash_length(32).personal(&perso).to_state();
    h_sighash.write_all(h_header.as_bytes())?;
    h_sighash.write_all(h_transparent.as_bytes())?;
    h_sighash.write_all(h_sapling.as_bytes())?;
    h_sighash.write_all(h_orchard.as_bytes())?;
    let h_sighash = h_sighash.finalize();

    let device_sighash = match index {
        None => {
            test_writer.ledger_confirm_fee()?; // confirm the fee only once
            test_writer.ledger_get_shielded_sighash()?
        },
        Some(_) => test_writer.ledger_get_transparent_sighash(txin_digest.unwrap().as_bytes())?,
    };
    println!("Sighash {:?}", h_sighash);
    println!("Ledger Sighash {:?}", hex::encode(&device_sighash));

    assert_eq!(h_sighash.as_bytes(), &device_sighash);

    Ok(h_sighash)
}
