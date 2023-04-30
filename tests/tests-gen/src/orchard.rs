use anyhow::Result;
use incrementalmerkletree::bridgetree::BridgeTree;
use incrementalmerkletree::Tree;
use orchard::builder::{InProgress, Unauthorized as OrchardUnAuth, Unproven};
use orchard::bundle::Flags;
use orchard::keys::{FullViewingKey, Scope};
use orchard::note::{Nullifier, RandomSeed};
use orchard::{Address, Anchor, Bundle, Note};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use zcash_primitives::transaction::components::orchard::Unauthorized as TxOrchardUnAuth;

use rand::RngCore;

use zcash_primitives::merkle_tree::Hashable;
use zcash_primitives::transaction::components::Amount;

use crate::random256;

fn random_orchard_note<R: RngCore>(recipient: Address, value: u64, mut rng: R) -> Note {
    let rho = Nullifier::dummy(&mut rng);
    let value = NoteValue::from_raw(value);
    let rseed = RandomSeed::random(&mut rng, &rho);
    let note = Note::from_parts(recipient, value, rho, rseed).unwrap();
    note
}

pub fn build_orchard_bundle<R: RngCore>(
    fvk: &FullViewingKey,
    recipient_address: &Address,
    spends: &[u64],
    outputs: &[u64],
    mut rng: R,
) -> Result<Option<Bundle<TxOrchardUnAuth, Amount>>> {
    if spends.is_empty() && outputs.is_empty() {
        return Ok(None);
    }
    let mut tree: BridgeTree<_, 32> = BridgeTree::new(1);

    let mut notes = vec![];
    for i in 0..100 {
        let (note, is_witness) = if i >= 10 && i < 10 + spends.len() {
            let note = random_orchard_note(recipient_address.clone(), spends[i - 10], &mut rng);
            notes.push(note.clone());
            (note, true)
        } else {
            let note = random_orchard_note(recipient_address.clone(), 0, &mut rng); // dummy notes
            (note, false)
        };
        let cmu = note.commitment();
        let node = MerkleHashOrchard::from_cmx(&cmu.into());
        tree.append(&node);
        if is_witness {
            tree.witness().unwrap();
        }
    }

    let anchor = tree.root(0).unwrap();
    let anchor: Anchor = anchor.into();
    let mut builder = orchard::builder::Builder::new(Flags::from_parts(true, true), anchor);
    let address = fvk.address_at(0u64, Scope::External);
    for sp in spends {
        let rho = Nullifier::from_bytes(&random256(&mut rng)).unwrap();
        let rseed = RandomSeed::from_bytes(random256(&mut rng), &rho).unwrap();
        let note = Note::from_parts(address.clone(), NoteValue::from_raw(*sp), rho, rseed).unwrap();
        let merkle_path = MerklePath::from_parts(0, [MerkleHashOrchard::blank(); 32]);
        builder.add_spend(fvk.clone(), note, merkle_path).unwrap();
    }
    for output in outputs {
        builder
            .add_recipient(
                None,
                recipient_address.clone(),
                NoteValue::from_raw(*output),
                None,
            )
            .unwrap();
    }
    let bundle: Bundle<InProgress<Unproven, OrchardUnAuth>, Amount> =
        builder.build(&mut rng).unwrap();
    let bundle: Bundle<TxOrchardUnAuth, Amount> =
        bundle.map_authorization(&mut (), |_, _, _| {}, |_, _| TxOrchardUnAuth {});
    Ok(Some(bundle))
}
