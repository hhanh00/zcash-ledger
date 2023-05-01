use anyhow::Result;
use incrementalmerkletree::bridgetree::BridgeTree;
use incrementalmerkletree::Tree;
use nonempty::NonEmpty;
use orchard::builder::{InProgress, SigningMetadata, SigningParts, Unauthorized as OrchardUnAuth, Unauthorized, Unproven};
use orchard::bundle::Flags;
use orchard::keys::{FullViewingKey, Scope, SpendValidatingKey};
use orchard::note::{ExtractedNoteCommitment, Nullifier, RandomSeed, TransmittedNoteCiphertext};
use orchard::tree::{MerkleHashOrchard};
use orchard::value::{NoteValue, ValueCommitment, ValueCommitTrapdoor, ValueSum};
use orchard::{Action, Address, Anchor, Bundle, Note};
use orchard::note_encryption::OrchardNoteEncryption;
use pasta_curves::pallas;


use rand::RngCore;



use zcash_primitives::transaction::components::Amount;
use crate::ledger_set_stage;
use crate::transport::{ledger_add_o_action, ledger_set_net_orchard};


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
) -> Result<Option<Bundle<InProgress<Unproven, Unauthorized>, Amount>>> {
    if spends.is_empty() && outputs.is_empty() {
        ledger_set_stage(5)?;
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

    let root = tree.root(0).unwrap();
    let anchor: Anchor = root.into();

    let num_actions = spends.len().max(outputs.len());
    let mut actions = vec![];
    let mut total_net = 0;
    for i in 0..num_actions {
        let spend_note = if i < spends.len() {
            notes[i]
        } else {
            random_orchard_note(recipient_address.clone(), 0, &mut rng)
        };
        let amount = if i < outputs.len() {
            outputs[i]
        } else {
            0
        };
        let rcv = ValueCommitTrapdoor::random(&mut rng);
        let output_note = random_orchard_note(recipient_address.clone(), amount, &mut rng);
        let rseed_bytes = output_note.rseed().as_bytes();
        let nf = spend_note.nullifier(fvk);
        let mut alpha = [0u8; 64];
        rng.fill_bytes(&mut alpha);
        let ak: SpendValidatingKey = fvk.clone().into();
        let rk = ak.randomize(&pallas::Scalar::zero());
        let cmx = output_note.commitment();
        let cmx: ExtractedNoteCommitment = cmx.into();
        let v_net: ValueSum = spend_note.value() - output_note.value();
        let vv = i64::try_from(v_net).unwrap();
        total_net += vv;
        let cv_net = ValueCommitment::derive(v_net, rcv.clone());

        let encryptor = OrchardNoteEncryption::new(
            Some(fvk.to_ovk(Scope::External)),
            output_note.clone(),
            recipient_address.clone(),
            [0; 512],
        );

        let epk = encryptor.epk().to_bytes().0;
        let enc = encryptor.encrypt_note_plaintext();
        let out = encryptor.encrypt_outgoing_plaintext(&cv_net.clone(), &cmx, &mut rng);
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: epk.clone(),
            enc_ciphertext: enc.clone(),
            out_ciphertext: out.clone(),
        };

        actions.push(Action::from_parts(
            nf, rk, cmx.into(), encrypted_note, cv_net, SigningMetadata {
                dummy_ask: None, parts: SigningParts { ak, alpha: Default::default() } }
        ));
        ledger_add_o_action(&nf.to_bytes(), amount, &epk, &recipient_address.to_raw_address_bytes(),
            &enc[0..52], rseed_bytes)?;
    }
    ledger_set_stage(5)?;

    let actions = NonEmpty::from_slice(&actions).unwrap();
    let bundle: Bundle<InProgress<Unproven, OrchardUnAuth>, Amount> = Bundle::from_parts(
        actions,
        Flags::from_parts(true, true),
        Amount::from_i64(total_net).unwrap(),
        anchor,
        InProgress::<Unproven, OrchardUnAuth>::empty()
    );
    ledger_set_net_orchard(total_net)?;

    Ok(Some(bundle))
}
