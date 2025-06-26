use std::cell::RefCell;

use tlv_parser::tlv::Tlv;
use tlv_parser::tlv::Value;

use super::AsymmetricKey;
use super::Error;

/// This struct is responsible for trying to read a piv card
/// Mutable member functions might cause a change in state of the card
/// such as locking out the pin if the incorrect pin is provided
/// See nist 800-73-4
pub struct PivCardReader<'a> {
    tx: pcsc::Transaction<'a>,
    aid: RefCell<Option<Vec<u8>>>,
    ccc: RefCell<Option<super::CardCapabilityContainer>>,
}

#[derive(Copy, Clone)]
#[repr(u8)]
pub enum Slot {
    Pin = 0x80,
    Puk = 0x81,
    Management = 0x9b,
    Retired00 = 0x82,
    Retired01 = 0x83,
    Retired02 = 0x84,
    Retired03 = 0x85,
    Retired04 = 0x86,
    Retired05 = 0x87,
    Retired06 = 0x88,
    Retired07 = 0x89,
    Retired08 = 0x8a,
    Retired09 = 0x8b,
    Retired10 = 0x8c,
    Retired11 = 0x8d,
    Retired12 = 0x8e,
    Retired13 = 0x8f,
    Retired14 = 0x90,
    Retired15 = 0x91,
    Retired16 = 0x92,
    Retired17 = 0x93,
    Retired18 = 0x94,
    Retired19 = 0x95,
    Authentication = 0x9a,
    Signing = 0x9c,
    KeyManagement = 0x9d,
    CardAuthentication = 0x9e,
    Attestation = 0xf9,
}

#[derive(Debug, Default)]
pub struct Discovery {
    pub aid: Vec<u8>,
    pub pin: Vec<u8>,
}

#[derive(Debug)]
pub enum RawPublicKey {
    RsaPublicKey { public: Vec<u8>, modulus: Vec<u8> },
}

impl RawPublicKey {
    pub fn to_der(&self) -> Vec<u8> {
        match self {
            RawPublicKey::RsaPublicKey { public, modulus } => yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    w.next().write_bigint_bytes(public, true);
                    w.next().write_bigint_bytes(modulus, true);
                })
            }),
        }
    }
}

/// Establish a connection with a card reader, waiting until it has a valid aid
/// This is required to overcome limitations of the software smartcard simulator
fn establish_with<T, F: FnOnce(PivCardReader<'_>) -> T>(reader_name: String, f: F) -> T {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("failed to establish context");
    loop {
        let mut card2;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let c2 = ctx.connect(
                &std::ffi::CString::new(reader_name.clone()).unwrap(),
                pcsc::ShareMode::Shared,
                pcsc::Protocols::ANY,
            );
            if let Ok(c) = c2 {
                card2 = c;
                break;
            }
        }
        let reader = PivCardReader::new(&mut card2);
        if reader.find_aid().is_ok() {
            return f(reader);
        }
    }
}

/// Iterate over all cards, with a filtering function, then running the specified closure on it
fn iterate_all_piv_cards<T, F, G>(filter: G, f: F) -> Result<T, ()>
where
    F: FnOnce(PivCardReader<'_>) -> T,
    G: Fn(&PivCardReader<'_>) -> bool,
{
    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("failed to establish context");
    let names = ctx.list_readers_owned().expect("failed to list readers");
    for name in names {
        let card = ctx.connect(&name, pcsc::ShareMode::Shared, pcsc::Protocols::ANY);
        if card.is_err() {
            continue;
        }
        let mut card = card.unwrap();
        let reader = PivCardReader::new(&mut card);
        if filter(&reader) {
            return Ok(f(reader));
        }
    }
    Err(())
}

/// Wait for the next valid piv card inserted
pub async fn with_next_valid_piv_card<T, F: FnOnce(PivCardReader<'_>) -> T>(f: F) -> T {
    let reader_name = super::wait_for_card(true).await;
    establish_with(reader_name, f)
}

/// Wait for a valid piv card inserted, even if it is already inserted
pub async fn with_current_valid_piv_card<T, F: FnOnce(PivCardReader<'_>) -> T>(f: F) -> T {
    let reader_name = super::wait_for_card(false).await;
    establish_with(reader_name, f)
}

/// Wait for a valild piv card with the specified public key in the specified slot
pub fn with_piv_and_public_key<T, F: Clone + FnOnce(PivCardReader<'_>) -> T>(
    slot: Slot,
    pubkey: &[u8],
    f: F,
    timeout: std::time::Duration,
) -> Result<T, ()> {
    let start = std::time::Instant::now();
    loop {
        if let Ok(a) = iterate_all_piv_cards(
            |reader| {
                if reader.find_aid().is_err() {
                    return false;
                }
                reader
                    .get_public_key(slot)
                    .map(|a| a.to_der() == pubkey)
                    .unwrap_or(false)
            },
            |reader| f.clone()(reader),
        ) {
            return Ok(a);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        if (std::time::Instant::now() - start) >= timeout {
            return Err(());
        }
    }
}

impl<'a> PivCardReader<'a> {
    /// Upgrade to a writer
    pub fn to_writer(self) -> PivCardWriter<'a> {
        PivCardWriter::extend(self)
    }

    /// Try to find a card with a specified public key
    pub fn search_for_public_key(&self, pubkey: &[u8]) -> Result<(), Error> {
        let a = self.get_public_key(Slot::Authentication).map(|rpk| {
            let der = rpk.to_der();
            if &der == pubkey {
                Ok(())
            } else {
                Err(())
            }
        });
        Ok(a.map(|_| ())?)
    }

    /// Construct a new self
    pub fn new(card: &'a mut pcsc::Card) -> Self {
        let tx = card
            .transaction()
            .expect("failed to begin card transaction");
        Self {
            tx,
            aid: RefCell::new(None),
            ccc: RefCell::new(None),
        }
    }

    /// Get the metadata about a key
    pub fn get_metadata(&self, slot: Slot) -> Result<super::Metadata, Error> {
        super::ApduCommand::get_metadata(&self.tx, slot as u8)
    }

    pub fn get_public_key(&self, slot: Slot) -> Result<RawPublicKey, Error> {
        let meta = self.get_metadata(slot)?;
        match meta.algorithm.ok_or(Error::AlgorithmMissing)? {
            crate::AuthenticateAlgorithm::TripleDes => todo!(),
            crate::AuthenticateAlgorithm::Rsa1024 | crate::AuthenticateAlgorithm::Rsa2048 => {
                let mut modulus = None;
                let mut public = None;
                let pdata = meta.public.unwrap();
                let tlv = tlv_parser::tlv::Tlv::from_vec(&pdata).unwrap();
                let len = tlv.len();
                let tlv2 = tlv_parser::tlv::Tlv::from_vec(&pdata[len..]).unwrap();
                if let tlv_parser::tlv::Value::Val(v) = tlv.val() {
                    public = Some(v.to_owned());
                }
                if let tlv_parser::tlv::Value::Val(v) = tlv2.val() {
                    modulus = Some(v.to_owned());
                }
                Ok(RawPublicKey::RsaPublicKey {
                    public: public.ok_or(Error::MissingPublicKey)?,
                    modulus: modulus.ok_or(Error::MissingModulus)?,
                })
            }
            crate::AuthenticateAlgorithm::Aes128 => todo!(),
            crate::AuthenticateAlgorithm::Aes192 => todo!(),
            crate::AuthenticateAlgorithm::EccP256 => todo!(),
            crate::AuthenticateAlgorithm::Aes256 => todo!(),
            crate::AuthenticateAlgorithm::EccP384 => todo!(),
            crate::AuthenticateAlgorithm::CipherSuite2 => todo!(),
            crate::AuthenticateAlgorithm::CipherSuite7 => todo!(),
        }
    }

    /// get the card capability container
    pub fn get_ccc(&self) -> Result<(), ()> {
        if self.ccc.borrow().is_none() {
            let mut ccc: super::CardCapabilityContainer = Default::default();
            let tlv = Tlv::new(0x5c, Value::Val(vec![0x5f, 0xc1, 0x07])).unwrap();
            let mut c = super::ApduCommand::new_get_data(tlv.to_vec());
            let r = c.run_command(&self.tx);
            if let Ok(r) = &r {
                if let Some(d) = &r.data {
                    let tlv = Tlv::from_vec(d).unwrap();
                    if let Value::Val(v) = tlv.val() {
                        let v: &[u8] = &v;
                        ccc = v.into();
                    }
                }
            }
            self.ccc.replace(Some(ccc));
        }
        Ok(())
    }

    /// Read the discovery object
    pub fn read_discovery(&self) -> Result<Discovery, Error> {
        let mut disc = Discovery::default();
        let a = self.get_tlv_data(vec![0x7e])?;
        if let Value::TlvList(tlvs) = a.val() {
            for tlv in tlvs {
                println!("TLV IS {}", tlv);
                if tlv.tag() == 0x4f {
                    if let Value::Val(v) = tlv.val() {
                        disc.aid = v.to_owned();
                    }
                }
                if tlv.tag() == 0x5f2f {
                    if let Value::Val(v) = tlv.val() {
                        disc.pin = v.to_owned();
                    }
                }
            }
            return Ok(disc);
        } else {
            return Err(Error::MalformedResponse);
        }
    }

    /// Find the aid from a limited list
    pub fn find_aid(&self) -> Result<(), ()> {
        let aids: Vec<Vec<u8>> = vec![vec![
            0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
        ]];
        for aid in aids {
            let mut c = super::ApduCommand::new_select_aid(aid.clone());
            let stat = c.run_command(&self.tx);
            if let Ok(mut s) = stat {
                if let super::ApduStatus::ResponseBytesRemaining(_d) = s.status {
                    s.get_full_response(&self.tx);
                }
                if let super::ApduStatus::CommandExecutedOk = s.status {
                    self.aid.replace(Some(aid));
                }
            }
        }
        if self.aid.borrow().is_some() {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Bruteforce the aid on the card
    pub fn bruteforce_aid(&self) -> Result<(), ()> {
        let mut aid = Vec::new();
        let mut any = false;
        loop {
            let mut found = false;
            for i in 0..=255 {
                let mut taid = aid.clone();
                taid.push(i as u8);
                let mut c = super::ApduCommand::new_select_aid(taid.to_owned());
                let stat = c.run_command(&self.tx);
                if let Ok(mut s) = stat {
                    if let super::ApduStatus::ResponseBytesRemaining(_d) = s.status {
                        s.get_full_response(&self.tx);
                    }
                    if let super::ApduStatus::CommandExecutedOk = s.status {
                        aid.push(i);
                        found = true;
                        any = true;
                    }
                }
            }
            if !found {
                break;
            }
        }

        let mut c = super::ApduCommand::new_select_aid(aid.to_owned());
        let mut stat = c.run_command(&self.tx).map_err(|_| ())?;
        if let super::ApduStatus::ResponseBytesRemaining(_d) = stat.status {
            stat.get_full_response(&self.tx);
        }
        if let super::ApduStatus::CommandExecutedOk = stat.status {
            self.aid.replace(Some(aid));
            if any {
                Ok(())
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }

    /// Try to get the x509 certificate
    pub fn get_x509_cert(&self, which: u8) -> Option<Vec<u8>> {
        let tlv = Tlv::new(0x5c, Value::Val(vec![0x5f, 0xc1, which])).unwrap();
        let mut c = super::ApduCommand::new_get_data(tlv.to_vec());
        let mut r = c.run_command(&self.tx);
        if let Ok(r) = &mut r {
            if let super::ApduStatus::ResponseBytesRemaining(_d) = r.status {
                r.get_full_response(&self.tx);
            }
            if let Some(d) = &r.data {
                let tlv = Tlv::from_vec(d).unwrap();
                if let Value::Val(v) = tlv.val() {
                    return Some(v.to_owned());
                }
            }
        }
        None
    }

    /// Try to get some piv data
    pub fn get_piv_data(&self, tag: Vec<u8>) -> Result<Vec<u8>, Error> {
        let tlv = self.get_tlv_data(tag)?;
        if let Value::Val(v) = tlv.val() {
            Ok(v.to_owned())
        } else {
            Err(Error::MalformedResponse)
        }
    }

    /// return the tlv data directly
    pub fn get_tlv_data(&self, tag: Vec<u8>) -> Result<Tlv, Error> {
        let tlv = Tlv::new(0x5c, Value::Val(tag)).unwrap();
        let mut c = super::ApduCommand::new_get_data(tlv.to_vec());
        let r = c.run_command(&self.tx).map_err(|e| Error::PcscError(e))?;
        if let Some(d) = &r.data {
            let tlv = Tlv::from_vec(d).unwrap();
            Ok(tlv)
        } else {
            Err(Error::ApduError(r.status))
        }
    }

    /// Authenticate with the piv pin
    pub fn piv_pin_auth(&mut self, pin: &[u8]) -> Result<(), Error> {
        let mut cmd = super::ApduCommand::new_verify_pin(pin, 0x80);
        let resp = cmd.run_command(&self.tx).unwrap();
        if let super::ApduStatus::CommandExecutedOk = resp.status {
            Ok(())
        } else {
            Err(Error::ApduError(resp.status))
        }
    }

    /// Sign some data
    pub fn sign_data(&mut self, slot: Slot, pin: &[u8], data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let metadata = self.get_metadata(slot)?;

        self.piv_pin_auth(pin)?;

        let algorithm = metadata.algorithm.unwrap();
        let tlv1 = Tlv::new(0x82, Value::Val(vec![])).unwrap();
        let tlv2 = Tlv::new(0x81, Value::Val(data)).unwrap();
        let tlvs = Value::TlvList(vec![tlv1, tlv2]);
        let total = Tlv::new(0x7c, Value::Val(tlvs.to_vec())).unwrap();
        let tlv_vec = total.to_vec();
        let mut cmd = super::ApduCommand::new_general_authenticate(algorithm, slot, &tlv_vec);
        let mut resp = cmd.run_command(&self.tx).map_err(|e| Error::PcscError(e))?;
        if let super::ApduStatus::ResponseBytesRemaining(_d) = resp.status {
            resp.get_full_response(&self.tx);
        }
        if let super::ApduStatus::CommandExecutedOk = resp.status {
            let tlv = Tlv::from_vec(resp.data.as_ref().unwrap()).unwrap();
            if let Value::TlvList(tlvs) = tlv.val() {
                for tlv in tlvs {
                    if tlv.tag() == 0x82 {
                        if let Value::Val(v) = tlv.val() {
                            return Ok(v.to_owned());
                        }
                    }
                }
                return Err(Error::MalformedResponse);
            } else {
                return Err(Error::MalformedResponse);
            }
        } else {
            return Err(Error::MalformedResponse);
        }
    }
}

pub const MANAGEMENT_KEY_DEFAULT: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

pub const PIV_PIN_KEY_DEFAULT: &[u8] = &[b'1', b'2', b'3', b'4', b'5', b'6'];

/// This struct is responsible for trying to modify a piv card
/// See nist 800-73-4
pub struct PivCardWriter<'a> {
    pub reader: PivCardReader<'a>,
}

impl<'a> PivCardWriter<'a> {
    /// Construct a new self
    pub fn new(card: &'a mut pcsc::Card) -> Self {
        Self {
            reader: PivCardReader::new(card),
        }
    }

    /// Extend a reader into a writer
    pub fn extend(reader: PivCardReader<'a>) -> Self {
        Self { reader }
    }

    /// Write the contents of a piv certificate, even if it exists
    pub fn store_x509_cert(
        &mut self,
        management_key: &[u8],
        data: &[u8],
        which: u8,
    ) -> Result<(), Error> {
        self.authenticate_management(management_key)?;
        println!("Storing cert data length {} {:02X?}", data.len(), data);
        let tlv1 = Tlv::new(0x70, Value::Val(data.to_owned())).unwrap();
        //let tlv2 = Tlv::new(0x71, Value::Val(vec![0])).unwrap();
        let tlv3 = Tlv::new(0xfe, Value::Val(vec![])).unwrap();
        let tlvs = Value::TlvList(vec![tlv1, tlv3]);
        self.write_piv_data(vec![0x5f, 0xc1, which], tlvs.to_vec())
    }

    /// Write the contents of a piv certificate if it does not exist on the card
    pub fn maybe_store_x509_cert(
        &mut self,
        management_key: &[u8],
        data: &[u8],
        which: u8,
    ) -> Result<(), Error> {
        if self.reader.get_x509_cert(which).is_none() {
            self.store_x509_cert(management_key, data, which)
        } else {
            Ok(())
        }
    }

    /// Update the discovery object, probably correct?
    pub fn update_discovery(
        &mut self,
        disc: &Discovery,
        management_key: &[u8],
    ) -> Result<(), Error> {
        let tlv1 = Tlv::new(0x4f, Value::Val(disc.aid.to_owned())).unwrap();
        let tlv2 = Tlv::new(0x5f2f, Value::Val(disc.pin.to_owned())).unwrap();
        let tlvs = Value::TlvList(vec![tlv1, tlv2]);
        let tag = Tlv::new(0x7e, Value::Val(tlvs.to_vec())).unwrap();
        println!("The discovery tag is {:02X?}", tag.to_vec());
        let mut cmd = super::ApduCommand::new_put_data(tag.to_vec());
        self.authenticate_management(management_key)?;
        let stat = cmd
            .run_command(&self.reader.tx)
            .map_err(|e| Error::PcscError(e))?;
        if let super::ApduStatus::CommandExecutedOk = stat.status {
            Ok(())
        } else {
            Err(Error::ApduError(stat.status))
        }
    }

    /// Attempt to erase the card
    pub fn erase_card(&mut self) -> Result<(), ()> {
        let mut erase = super::ApduCommand::new_erase_card();
        let _erases = erase.run_command(&self.reader.tx);
        todo!();
    }

    pub fn authenticate_management(&mut self, management_key: &[u8]) -> Result<(), Error> {
        let md = self.reader.get_metadata(Slot::Management)?;
        let algorithm = md
            .algorithm
            .clone()
            .unwrap_or_else(|| super::AuthenticateAlgorithm::Rsa2048);

        let mut c = super::ApduCommand::new_authenticate_management1(algorithm, false);
        let stat = c.run_command(&self.reader.tx).unwrap();
        if let super::ApduStatus::CommandExecutedOk = stat.status {
            let challenge = stat.process_response_authenticate1();
            let mut c2 = super::ApduCommand::new_authenticate_management2(
                algorithm,
                challenge.as_ref().unwrap(),
                management_key,
            );
            let stat2 = c2.run_command(&self.reader.tx);
            let e = stat2.as_ref().unwrap().status;
            if let super::ApduStatus::CommandExecutedOk = e {
                Ok(())
            } else {
                Err(Error::ApduError(e))
            }
        } else {
            Err(Error::ApduError(stat.status))
        }
    }

    fn generate_keypair(
        &mut self,
        algorithm: super::AuthenticateAlgorithm,
        slot: Slot,
        pin_policy: super::KeypairPinPolicy,
    ) -> Result<AsymmetricKey, Error> {
        let meta = self.reader.get_metadata(slot)?;
        let algorithm = meta.algorithm.unwrap_or(algorithm);
        let mut cmd = super::ApduCommand::new_generate_asymmetric_key_pair(
            slot as u8,
            algorithm,
            pin_policy,
            super::KeypairTouchPolicy::Never,
        );
        let mut r = cmd
            .run_command(&self.reader.tx)
            .map_err(|e| Error::PcscError(e))?;
        if let super::ApduStatus::ResponseBytesRemaining(_d) = r.status {
            r.get_full_response(&self.reader.tx);
        }
        if let super::ApduStatus::CommandExecutedOk = r.status {
            let lkey = r.parse_asymmetric_key_response(algorithm)?;
            Ok(lkey)
        } else {
            Err(Error::ApduError(r.status))
        }
    }

    /// Generate an asymmetric keypair in the given slot
    pub fn generate_keypair_with_management(
        &mut self,
        management_key: &[u8],
        algorithm: super::AuthenticateAlgorithm,
        slot: Slot,
        pin_policy: super::KeypairPinPolicy,
    ) -> Result<AsymmetricKey, Error> {
        self.authenticate_management(management_key)?;
        self.generate_keypair(algorithm, slot, pin_policy)
    }

    /// Write some data into a piv data object
    pub fn write_piv_data(&mut self, tag: Vec<u8>, data: Vec<u8>) -> Result<(), Error> {
        let tlv = Tlv::new(0x5c, tlv_parser::tlv::Value::Val(tag)).unwrap();
        let tlv2 = Tlv::new(0x53, tlv_parser::tlv::Value::Val(data)).unwrap();
        let tlv_total = tlv_parser::tlv::Value::TlvList(vec![tlv, tlv2]);
        let mut c = super::ApduCommand::new_put_data(tlv_total.to_vec());
        let r = c.run_command(&self.reader.tx);
        match r {
            Ok(r) => {
                if let Some(d) = &r.data {
                    let tlv = Tlv::from_vec(d).unwrap();
                    println!("Tlv of write data is {}", tlv);
                } else {
                    println!("Total response is {:02X?}", r);
                }
                Ok(())
            }
            Err(e) => Err(Error::PcscError(e)),
        }
    }
}
