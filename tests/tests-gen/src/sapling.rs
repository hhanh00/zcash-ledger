use anyhow::Result;
use incrementalmerkletree::bridgetree::BridgeTree;
use incrementalmerkletree::{Altitude, Hashable, Tree};
use rand::RngCore;
use std::io::Write;

use byteorder::{WriteBytesExt, LE};
use jubjub::Scalar;

use zcash_primitives::consensus::{MainNetwork};
use zcash_primitives::constants::SPENDING_KEY_GENERATOR;
use zcash_primitives::memo::{MemoBytes};
use zcash_primitives::merkle_tree::MerklePath;
use zcash_primitives::sapling::note_encryption::sapling_note_encryption;
use zcash_primitives::sapling::redjubjub::PublicKey;
use zcash_primitives::sapling::{merkle_hash, Note, PaymentAddress, Rseed};

use crate::{random256, TestWriter};
use zcash_primitives::sapling::value::{
    NoteValue, TrapdoorSum, ValueCommitTrapdoor, ValueCommitment,
};
use zcash_primitives::transaction::components::sapling::builder::{
    SaplingMetadata, SpendDescriptionInfo, Unauthorized,
};
use zcash_primitives::transaction::components::sapling::Bundle;
use zcash_primitives::transaction::components::{
    Amount, OutputDescription, SpendDescription,
};
use zcash_primitives::zip32::ExtendedSpendingKey;

fn random_sapling_note<R: RngCore>(address: &PaymentAddress, value: u64, mut rng: R) -> Note {
    let rseed = random256(&mut rng);
    let rseed = Rseed::AfterZip212(rseed);
    let note = Note::from_parts(address.clone(), NoteValue::from_raw(value), rseed);
    note
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct SaplingMerkleHash([u8; 32]);

impl Hashable for SaplingMerkleHash {
    fn empty_leaf() -> Self {
        SaplingMerkleHash([0; 32])
    }

    fn combine(level: Altitude, a: &Self, b: &Self) -> Self {
        let h = merkle_hash(level.into(), &a.0, &b.0);
        SaplingMerkleHash(h)
    }
}

pub fn build_sapling_bundle<R: RngCore>(
    sk: &ExtendedSpendingKey,
    recipient_address: &PaymentAddress,
    spends: &[u64],
    outputs: &[u64],
    test_writer: &mut TestWriter,
    mut rng: R,
) -> Result<Option<Bundle<Unauthorized>>> {
    let mut notes = vec![];
    if spends.is_empty() && outputs.is_empty() {
        test_writer.ledger_set_stage(4)?;
        return Ok(None);
    }
    let dfvk = sk.to_diversifiable_full_viewing_key();

    let (_, address) = dfvk.default_address();
    let _d = address.diversifier();

    let mut tree: BridgeTree<_, 32> = BridgeTree::new(1);

    for i in 0..100 {
        let (note, is_witness) = if i >= 10 && i < 10 + spends.len() {
            let note = random_sapling_note(&address, spends[i - 10], &mut rng);
            notes.push(note.clone());
            (note, true)
        } else {
            let note = random_sapling_note(&address, 0, &mut rng); // dummy notes
            (note, false)
        };
        let cmu = note.cmu().to_bytes();
        let node = SaplingMerkleHash(cmu);
        tree.append(&node);
        if is_witness {
            tree.witness().unwrap();
        }
    }

    let anchor = tree.root(0).unwrap();

    let diversifier = address.diversifier();

    let mut value_balance = 0;
    let mut shielded_spends = vec![];
    let proof_generation_key = sk.expsk.proof_generation_key();
    let nk = proof_generation_key.to_viewing_key().nk;
    let mut bsk = TrapdoorSum::zero();
    for (note, (&p, _)) in notes.iter().zip(tree.witnessed_indices()) {
        let path = tree.authentication_path(p.clone(), &anchor).unwrap();
        let mut witness = vec![];
        witness.write_u8(path.len() as u8)?;
        for hash in path.iter().rev() {
            witness.write_u8(32)?;
            witness.write_all(&hash.0)?;
        }
        let position: u64 = p.into();
        witness.write_u64::<LE>(position)?;
        let merkle_path = MerklePath::from_slice(&witness).unwrap();
        let mut alpha = [0u8; 64];
        rng.fill_bytes(&mut alpha);
        let alpha = Scalar::from_bytes_wide(&alpha);
        let nullifier = note.nf(&nk, position);
        let rcv = ValueCommitTrapdoor::random(&mut rng);
        bsk += &rcv;
        let cv = ValueCommitment::derive(note.value, rcv);
        let rk = PublicKey(proof_generation_key.ak.into()).randomize(alpha, SPENDING_KEY_GENERATOR);
        value_balance += note.value.inner() as i64;

        shielded_spends.push(SpendDescription {
            cv,
            anchor: jubjub::Base::from_bytes(&anchor.0).unwrap(),
            nullifier,
            rk,
            zkproof: [0; 192],
            spend_auth_sig: SpendDescriptionInfo {
                extsk: sk.clone(),
                diversifier: diversifier.clone(),
                note: note.clone(),
                alpha,
                merkle_path,
            },
        });
    }

    let mut shielded_outputs = vec![];
    for output in outputs {
        let mut rseed_bytes = [0u8; 32];
        rng.fill_bytes(&mut rseed_bytes);
        let rseed = Rseed::AfterZip212(rseed_bytes);
        let note = Note::from_parts(
            recipient_address.clone(),
            NoteValue::from_raw(*output),
            rseed,
        );
        let rcv = ValueCommitTrapdoor::random(&mut rng);
        bsk -= &rcv;
        let cv = ValueCommitment::derive(note.value, rcv);
        let cmu = note.cmu();
        value_balance -= *output as i64;
        let encryptor = sapling_note_encryption::<R, MainNetwork>(
            None,
            note,
            recipient_address.clone(),
            MemoBytes::empty(),
            &mut rng,
        );
        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);
        let epk = encryptor.epk();
        shielded_outputs.push(OutputDescription {
            cv,
            cmu,
            ephemeral_key: epk.to_bytes(),
            enc_ciphertext,
            out_ciphertext,
            zkproof: [0; 192],
        });
        let ledger_cmu = test_writer.ledger_add_s_output(*output, epk.to_bytes().as_ref(),
            &recipient_address.to_bytes(), &enc_ciphertext[0..52], &rseed_bytes)?;
        assert_eq!(&ledger_cmu, &cmu.to_bytes())
    }
    test_writer.ledger_set_stage(4)?;

    test_writer.ledger_set_net_sapling(value_balance.into())?;

    let bundle: Bundle<Unauthorized> = Bundle::from_parts(
        shielded_spends,
        shielded_outputs,
        Amount::from_i64(value_balance).unwrap(),
        Unauthorized {
            tx_metadata: SaplingMetadata::empty(),
        },
    );

    Ok(Some(bundle))
}
