use std::fs::File;
use anyhow::{anyhow, Result};
use byteorder::WriteBytesExt;
use byteorder::LE;
use hex_literal::hex;
use reqwest::blocking::Client;
use serde_json::Value;
use std::io::{BufWriter, Write};
use std::path::Path;
use struson::writer::{JsonStreamWriter, JsonWriter};

const TEST_SERVER_IP: Option<&'static str> = option_env!("LEDGER_IP");

pub struct TestWriter {
    json_writer: JsonStreamWriter<BufWriter<File>>,
}

impl TestWriter {
    pub fn new(test_file: &Path) -> Self {
        let file = File::create(test_file).unwrap();
        let writer = BufWriter::new(file);
        let mut json_writer = JsonStreamWriter::new(writer);
        json_writer.begin_array().unwrap();
        TestWriter {
            json_writer,
        }
    }

    pub fn close(mut self) {
        self.json_writer.end_array().unwrap();
        self.json_writer.finish_document().unwrap();
    }

    fn handle_error_code(code: u16) -> Result<()> {
        match code {
            0x9000 => Ok(()),
            0x6D02 => Err(anyhow!("Zcash Application NOT OPEN")),
            0x6985 => Err(anyhow!("Tx REJECTED by User")),
            0x5515 => Err(anyhow!("Ledger is LOCKED")),
            _ => Err(anyhow!("Ledger device returned error code {:#06x}", code)),
        }
    }

    fn apdu(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.json_writer.begin_object()?;
        self.json_writer.name("req").unwrap();
        self.json_writer.string_value(&hex::encode(data)).unwrap();
        let client = Client::new();
        let response = client
            .post(&format!("http://{}:5000/apdu", TEST_SERVER_IP.unwrap()))
            .body(format!("{{\"data\": \"{}\"}}", hex::encode(data)))
            .send()?;
        let response_body: Value = response.json()?;
        let data = response_body["data"]
            .as_str()
            .ok_or(anyhow!("No data field"))?;
        let data = hex::decode(data)?;
        self.json_writer.name("rep").unwrap();
        self.json_writer.string_value(&hex::encode(&data)).unwrap();
        let error_code = u16::from_be_bytes(data[data.len() - 2..].try_into().unwrap());
        Self::handle_error_code(error_code)?;
        self.json_writer.end_object()?;
        Ok(data[..data.len() - 2].to_vec())
    }

    pub fn ledger_init_tx(&mut self, tx_name: &str) -> Result<Vec<u8>> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E010000000"))?;
        self.json_writer.begin_object()?;
        self.json_writer.name("test_name")?;
        self.json_writer.string_value(tx_name)?;
        self.json_writer.name("messages")?;
        self.json_writer.begin_array()?;
        let main_seed = self.apdu(&bb)?;
        Ok(main_seed)
    }

    pub fn ledger_set_stage(&mut self, stage: u8) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E011"))?;
        bb.write_u8(stage)?;
        bb.write_all(&hex!("0000"))?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_add_t_input(&mut self, amount: u64) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E012000008"))?;
        bb.write_u64::<LE>(amount)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_add_t_output(&mut self, amount: u64, address_type: u8, address: &[u8]) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E01300001D"))?;
        bb.write_u64::<LE>(amount)?;
        bb.write_u8(address_type)?;
        bb.write_all(address)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_add_s_output(
        &mut self,
        amount: u64,
        epk: &[u8],
        address: &[u8],
        enc_compact: &[u8],
        rseed: &[u8],
    ) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E0140000A7"))?;
        bb.write_all(address)?;
        bb.write_u64::<LE>(amount)?;
        bb.write_all(epk)?;
        bb.write_all(enc_compact)?;
        bb.write_all(rseed)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_add_o_action(
        &mut self,
        nf: &[u8],
        amount: u64,
        epk: &[u8],
        address: &[u8],
        enc_compact: &[u8],
        rseed: &[u8],
    ) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E0150000C7"))?;
        bb.write_all(nf)?;
        bb.write_all(address)?;
        bb.write_u64::<LE>(amount)?;
        bb.write_all(epk)?;
        bb.write_all(enc_compact)?;
        bb.write_all(rseed)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_set_net_sapling(&mut self, net: i64) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E016000008"))?;
        bb.write_i64::<LE>(net)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_set_net_orchard(&mut self, net: i64) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E017000008"))?;
        bb.write_i64::<LE>(net)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_set_header_digest(
        &mut self,
        header_digest: &[u8],
    ) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E018000020"))?;
        bb.write_all(header_digest)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_set_transparent_merkle_proof(
        &mut self,
        prevouts_digest: &[u8],
        pubscripts_digest: &[u8],
        sequences_digest: &[u8],
    ) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E019000060"))?;
        bb.write_all(prevouts_digest)?;
        bb.write_all(pubscripts_digest)?;
        bb.write_all(sequences_digest)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_set_sapling_merkle_proof(
        &mut self,
        spends_digest: &[u8],
        memos_digest: &[u8],
        outputs_nc_digest: &[u8],
    ) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E01A000060"))?;
        bb.write_all(spends_digest)?;
        bb.write_all(memos_digest)?;
        bb.write_all(outputs_nc_digest)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_set_orchard_merkle_proof(
        &mut self,
        anchor: &[u8],
        memos_digest: &[u8],
        outputs_nc_digest: &[u8],
    ) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E01B000060"))?;
        bb.write_all(anchor)?;
        bb.write_all(memos_digest)?;
        bb.write_all(outputs_nc_digest)?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_confirm_fee(&mut self) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E01C000000"))?;
        self.apdu(&bb)?;
        Ok(())
    }

    pub fn ledger_get_transparent_sighash(&mut self, txin_digest: &[u8]) -> Result<Vec<u8>> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E083000020"))?;
        bb.write_all(txin_digest)?;
        let sighash = self.apdu(&bb)?;
        Ok(sighash)
    }

    pub fn ledger_get_shielded_sighash(&mut self) -> Result<Vec<u8>> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E084000000"))?;
        let sighash = self.apdu(&bb)?;
        Ok(sighash)
    }

    pub fn ledger_end_tx(&mut self) -> Result<()> {
        let mut bb: Vec<u8> = vec![];
        bb.write_all(&hex!("E030000000"))?;
        self.apdu(&bb)?;
        self.json_writer.end_array()?;
        self.json_writer.end_object()?;
        Ok(())
    }
}
