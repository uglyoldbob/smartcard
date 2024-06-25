use tlv_parser::tlv::Tlv;

use crate::AsymmetricKey;

/// This struct is responsible for trying to read a piv card
/// See nist 800-73-4
pub struct PivCardReader<'a> {
    tx: pcsc::Transaction<'a>,
    aid: Option<Vec<u8>>,
    ccc: Option<super::CardCapabilityContainer>,
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

impl<'a> PivCardReader<'a> {
    /// Construct a new self
    pub fn new(card: &'a mut pcsc::Card) -> Self {
        let tx = card
            .transaction()
            .expect("failed to begin card transaction");
        Self {
            tx,
            aid: None,
            ccc: None,
        }
    }

    /// Get the metadata about a key
    fn get_metadata(&mut self, slot: Slot) -> Option<super::Metadata> {
        super::ApduCommand::get_metadata(&self.tx, slot as u8)
    }

    /// get the card capability container
    pub fn get_ccc(&mut self) -> Result<(), ()> {
        let mut ccc: super::CardCapabilityContainer = Default::default();
        let tlv =
            tlv_parser::tlv::Tlv::new(0x5c, tlv_parser::tlv::Value::Val(vec![0x5f, 0xc1, 0x07]))
                .unwrap();
        let mut c = super::ApduCommand::new_get_data(tlv.to_vec());
        let r = c.run_command(&self.tx);
        if let Ok(r) = &r {
            if let Some(d) = &r.data {
                let tlv = Tlv::from_vec(d).unwrap();
                if let tlv_parser::tlv::Value::Val(v) = tlv.val() {
                    let v: &[u8] = &v;
                    ccc = v.into();
                }
            }
        }
        println!("CCC IS {:02X?}", ccc);
        self.ccc = Some(ccc);
        Ok(())
    }

    /// Bruteforce the aid on the card
    pub fn bruteforce_aid(&mut self) -> Result<(), ()> {
        let mut aid = Vec::new();

        loop {
            let mut found = false;
            for i in 0..=255 {
                let mut taid = aid.clone();
                taid.push(i as u8);
                let mut c = super::ApduCommand::new_select_aid(taid.to_owned());
                let stat = c.run_command(&self.tx);
                if let Ok(s) = stat {
                    if let super::ApduStatus::CommandExecutedOk = s.status {
                        aid.push(i);
                        println!("AID is {:02X?}", aid);
                        found = true;
                    }
                }
            }
            if !found {
                break;
            }
        }
        println!("AID is {:02X?}", aid);

        let mut c = super::ApduCommand::new_select_aid(aid.to_owned());
        let stat = c.run_command(&self.tx).map_err(|_| ())?;
        println!("Selecting detected aid {:02X?}", stat);
        self.aid = Some(aid);
        Ok(())
    }

    /// Try to get the x509 certificate
    pub fn get_x509_cert(&self) -> Option<Vec<u8>> {
        let tlv = Tlv::new(0x5c, tlv_parser::tlv::Value::Val(vec![0x5f, 0xc1, 0x05])).unwrap();
        let mut c = super::ApduCommand::new_get_data(tlv.to_vec());
        let r = c.run_command(&self.tx);
        if let Ok(r) = &r {
            if let Some(d) = &r.data {
                let tlv = Tlv::from_vec(d).unwrap();
                println!("Tlv of x509 cert is {}", tlv);
            } else {
                println!("Total response is {:02X?}", r);
            }
        } else {
            println!("Error for get x509 cert is {:?}", r.err());
        }
        None
    }
}

const MANAGEMENT_KEY_DEFAULT: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// This struct is responsible for trying to mmodify a piv card
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

    /// Create a piv certificate if it does not exist
    pub fn maybe_create_x509_cert(&mut self) -> Result<(), ()> {
        Err(())
    }

    /// Attempt to erase the card
    pub fn erase_card(&mut self) -> Result<(), ()> {
        let mut erase = super::ApduCommand::new_erase_card();
        let erases = erase.run_command(&self.reader.tx);
        println!("Response of erase is {:02X?}", erases);
        Err(())
    }

    fn authenticate(&mut self) -> Result<(), ()> {
        let md = self.reader.get_metadata(Slot::Management).unwrap();
        println!("Metadata is {:02x?}", md);

        let algorithm = md
            .algorithm
            .clone()
            .unwrap_or_else(|| super::AuthenticateAlgorithm::Rsa2048);

        let mut c = super::ApduCommand::new_authenticate_management1(algorithm, false);
        let stat = c.run_command(&self.reader.tx).unwrap();
        println!("Status of authenticate1 is {:02x?}", stat);
        if let super::ApduStatus::CommandExecutedOk = stat.status {
            let challenge = stat.process_response_authenticate_management1();
            println!("Need to finish authentication now with {:02X?}", challenge);
            let mut c2 = super::ApduCommand::new_authenticate_management2(
                algorithm,
                challenge.as_ref().unwrap(),
                MANAGEMENT_KEY_DEFAULT,
            );
            let stat2 = c2.run_command(&self.reader.tx);
            println!("Response of auth2 is {:02X?}", stat2);
            if let super::ApduStatus::CommandExecutedOk = stat2.as_ref().unwrap().status {
                println!("Success auth2");
                Ok(())
            } else {
                println!("NOT success auth2");
                Err(())
            }
        } else if let super::ApduStatus::IncorrectParameter = stat.status {
            println!("Need to initialize management key?");
            let mut c = super::ApduCommand::new_set_management_key(
                super::ManagementKeyTouchPolicy::NoTouch,
                algorithm,
                [42; 24],
            );
            let stat = c.run_command(&self.reader.tx);
            println!("Status of set management key is {:02x?}", stat);
            Err(())
        } else {
            Err(())
        }
    }

    /// Generate an asymmetric keypair in the given slot
    pub fn generate_keypair(
        &mut self,
        slot: Slot,
        pin_policy: super::KeypairPinPolicy,
    ) -> Result<AsymmetricKey, ()> {
        self.authenticate()?;
        let metadata = self.reader.get_metadata(slot);
        let mut key: Option<AsymmetricKey> = None;
        if let Some(meta) = metadata {
            let mut cmd = super::ApduCommand::new_generate_asymmetric_key_pair(
                slot as u8,
                meta.algorithm
                    .unwrap_or_else(|| super::AuthenticateAlgorithm::Rsa2048),
                pin_policy,
                super::KeypairTouchPolicy::Never,
            );
            let r = cmd.run_command(&self.reader.tx);
            if let Ok(mut r) = r {
                if let super::ApduStatus::ResponseBytesRemaining(_d) = r.status {
                    r.get_full_response(&self.reader.tx);
                }
                if let super::ApduStatus::CommandExecutedOk = r.status {
                    println!("Command executed correctly");
                    let lkey =
                        r.parse_asymmetric_key_response(super::AuthenticateAlgorithm::Rsa2048);
                    println!("The key is {:02X?}", lkey);
                    key = lkey;
                } else {
                    println!("Status of generate keypair is {:?}", r.status);
                }
            }
        }
        Ok(key.unwrap())
    }
}
