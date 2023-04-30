use anyhow::Result;
use incrementalmerkletree::bridgetree::BridgeTree;
use incrementalmerkletree::{Altitude, Hashable, Tree};
use rand::RngCore;
use std::io::Write;
use std::str::FromStr;

use byteorder::{WriteBytesExt, LE};
use zcash_primitives::consensus::{BlockHeight, Network};
use zcash_primitives::memo::Memo;
use zcash_primitives::merkle_tree::MerklePath;
use zcash_primitives::sapling::{merkle_hash, Note, PaymentAddress, Rseed};

use crate::random256;
use zcash_primitives::sapling::value::NoteValue;
use zcash_primitives::transaction::components::sapling::builder::{SaplingBuilder, Unauthorized};
use zcash_primitives::transaction::components::sapling::Bundle;
use zcash_primitives::zip32::ExtendedSpendingKey;
use zcash_proofs::prover::LocalTxProver;
use zcash_proofs::sapling::SaplingProvingContext;

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
    network: Network,
    sk: &ExtendedSpendingKey,
    recipient_address: &PaymentAddress,
    spends: &[u64],
    outputs: &[u64],
    prover: &LocalTxProver,
    mut rng: R,
) -> Result<Option<Bundle<Unauthorized>>> {
    if spends.is_empty() && outputs.is_empty() {
        return Ok(None);
    }
    let dfvk = sk.to_diversifiable_full_viewing_key();

    let (_, address) = dfvk.default_address();

    let mut tree: BridgeTree<_, 32> = BridgeTree::new(1);

    let mut notes = vec![];
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

    let mut sapling_builder =
        SaplingBuilder::new(network.clone(), BlockHeight::from_u32(1_000_000));
    let d = address.diversifier();

    for (note, (&p, _)) in notes.iter().zip(tree.witnessed_indices()) {
        let path = tree.authentication_path(p.clone(), &anchor).unwrap();
        let mut witness = vec![];
        witness.write_u8(path.len() as u8)?;
        for hash in path.iter().rev() {
            witness.write_u8(32)?;
            witness.write_all(&hash.0)?;
        }
        witness.write_u64::<LE>(p.into())?;
        let path = MerklePath::from_slice(&witness).unwrap();
        sapling_builder
            .add_spend(&mut rng, sk.clone(), d.clone(), note.clone(), path)
            .unwrap();
    }

    for output in outputs {
        sapling_builder
            .add_output(
                &mut rng,
                None,
                recipient_address.clone(),
                NoteValue::from_raw(*output),
                Memo::from_str("Text Memo").unwrap().into(),
            )
            .unwrap();
    }

    let mut ctx = SaplingProvingContext::new();
    println!("Building");
    let bundle = sapling_builder
        .build(
            prover,
            &mut ctx,
            &mut rng,
            BlockHeight::from_u32(1_000_000),
            None,
        )
        .unwrap();

    Ok(Some(bundle.unwrap()))
}
