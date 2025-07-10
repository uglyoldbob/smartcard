#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]
#![allow(unused)]

//! Smartcard piv library.

pub mod atr;
pub mod historical;

use std::io::Read;

use des::cipher::{generic_array::GenericArray, BlockEncrypt};
use omnom::ReadExt;
use tlv_parser::tlv::{Tlv, Value};

/// The status of an APDU command.
#[derive(Copy, Clone, Debug)]
pub enum ApduStatus {
    /// Selecting an applet failed
    AppletSelectFailed,
    /// The class of the APDU command is not supported.
    ClassNotSupported,
    /// The command worked just fine
    CommandExecutedOk,
    /// The command was not allowed because there is no current EF.
    CommandNotAllowedNoCurrentEF,
    /// The command was not allowed because the file was not found.
    FileNotFound,
    /// The command was not allowed because the function is not supported.
    FunctionNotSupported,
    /// The data parameter is incorrect.
    IncorrectDataParameter,
    /// The P1 or P2 parameter for the command is incorrect.
    IncorrectP1P2Parameter,
    /// There are more response bytes remaining
    ResponseBytesRemaining(u8),
    /// Security checks failed for some reason
    SecurityFailed,
    /// The response is unknown
    UnknownResponse([u8; 2]),
}

/// The errors for this library
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// The apdu command experienced an error
    ApduError(ApduStatus),
    /// There was a pcsc specific error that occurred
    PcscError(pcsc::Error),
    /// The expected data for the command is missing
    ExpectedDataMissing,
    /// An algorithm needed is missing
    AlgorithmMissing,
    /// The public key is missing
    MissingPublicKey,
    /// The modulus is missing
    MissingModulus,
    /// The response is malformed
    MalformedResponse,
}

impl From<[u8; 2]> for ApduStatus {
    fn from(value: [u8; 2]) -> Self {
        match (value[0], value[1]) {
            (6, _) => Self::ClassNotSupported,
            (0x61, d) => Self::ResponseBytesRemaining(d),
            (0x69, 0x82) => Self::SecurityFailed,
            (0x69, 0x86) => Self::CommandNotAllowedNoCurrentEF,
            (0x69, 0x99) => Self::AppletSelectFailed,
            (0x6a, 0x80) => Self::IncorrectDataParameter,
            (0x6a, 0x86) => Self::IncorrectP1P2Parameter,
            (0x6a, 0x81) => Self::FunctionNotSupported,
            (0x6a, 0x82) => Self::FileNotFound,
            (0x90, 0x00) => Self::CommandExecutedOk,
            _ => Self::UnknownResponse(value),
        }
    }
}

/// Represents a response to a command to a smartcard
#[derive(Debug)]
pub struct ApduResponse {
    /// The optional data returned by the smartcard
    pub data: Option<Vec<u8>>,
    /// The status of the command issued to the smartcard
    pub status: ApduStatus,
}

impl ApduResponse {
    /// Process response to authenticate management1 command
    pub fn process_response_authenticate1(&self) -> Option<Vec<u8>> {
        self.data
            .as_ref()
            .map(|d| {
                if d.len() >= 4 && d[0..4] == [0x7c, 0x0a, 0x81, 0x08] {
                    let d2 = d[4..].to_vec();
                    Some(d2)
                } else {
                    None
                }
            })
            .flatten()
    }

    /// Get the full response, issuing additional read commands if necessary
    pub fn get_full_response(&mut self, tx: &pcsc::Transaction) {
        let mut r = Vec::new();
        if let Some(d) = &self.data {
            r.append(&mut d.clone());
        }
        while let ApduStatus::ResponseBytesRemaining(d) = self.status {
            let mut c = ApduCommand::new_get_response(d);
            *self = c.run_command(tx).unwrap();
            if let Some(d) = &self.data {
                r.append(&mut d.clone());
            }
        }
        self.data = Some(r);
    }

    /// Process generate asymmetric key response, required to call get_full_response first
    pub fn parse_asymmetric_key_response(
        &self,
        algorithm: AuthenticateAlgorithm,
    ) -> Result<AsymmetricKey, Error> {
        let d = self.data.as_ref().unwrap();
        match algorithm {
            AuthenticateAlgorithm::TripleDes => todo!(),
            AuthenticateAlgorithm::Rsa1024 => todo!(),
            AuthenticateAlgorithm::Rsa2048 => {
                let tlv = Tlv::from_vec(&d[0..]).unwrap();
                if let Value::TlvList(tlvs) = tlv.val() {
                    let rsa = AsymmetricRsaKey {
                        modulus: tlvs[0].val().to_vec(),
                        exponent: tlvs[1].val().to_vec(),
                    };
                    return Ok(AsymmetricKey::RsaKey(rsa));
                } else {
                    return Err(Error::MalformedResponse);
                }
            }
            AuthenticateAlgorithm::Aes128 => todo!(),
            AuthenticateAlgorithm::Aes192 => todo!(),
            AuthenticateAlgorithm::EccP256 => todo!(),
            AuthenticateAlgorithm::Aes256 => todo!(),
            AuthenticateAlgorithm::EccP384 => todo!(),
            AuthenticateAlgorithm::CipherSuite2 => todo!(),
            AuthenticateAlgorithm::CipherSuite7 => todo!(),
        }
    }
}

impl From<&[u8]> for ApduResponse {
    fn from(value: &[u8]) -> Self {
        let v = value.len() - 2;
        let a: [u8; 2] = [value[v], value[v + 1]];
        let status = a.into();
        let data = if v > 0 {
            let d = value[0..v].to_vec();
            Some(d)
        } else {
            None
        };
        Self { data, status }
    }
}

/// The main body of an apdu command to a smartcard
#[derive(Debug)]
pub struct ApduBody {
    /// The data of the command
    data: Vec<u8>,
    /// If Some, represents number of bytes expected.
    rlen: Option<u32>,
}

/// Represents a complete apdu command to a smartcard
#[derive(Debug)]
pub struct ApduCommand {
    /// The instruction class
    cla: u8,
    /// The instruction code
    ins: u8,
    /// The parameter 1
    p1: u8,
    /// The parameter 2
    p2: u8,
    /// The body of the command
    body: Option<ApduBody>,
    /// The response of the command
    response: Option<ApduResponse>,
}

impl ApduCommand {
    /// Build a new select aid command
    pub fn new_select_aid(f: Vec<u8>) -> Self {
        Self {
            cla: 0,
            ins: 0xa4,
            p1: 4,
            p2: 0,
            body: Some(ApduBody {
                data: f,
                rlen: None,
            }),
            response: None,
        }
    }

    /// Create a new get response command
    pub fn new_get_response(d: u8) -> Self {
        Self {
            cla: 0,
            ins: 0xc0,
            p1: 0,
            p2: 0,
            body: Some(ApduBody {
                data: Vec::new(),
                rlen: Some(d as u32),
            }),
            response: None,
        }
    }

    /// The get data command
    pub fn new_get_data(tag: Vec<u8>) -> Self {
        Self {
            cla: 0,
            ins: 0xcb,
            p1: 0x3f,
            p2: 0xff,
            body: Some(ApduBody {
                data: tag,
                rlen: None,
            }),
            response: None,
        }
    }

    /// Set the management key
    pub fn new_set_management_key(
        touch_policy: ManagementKeyTouchPolicy,
        algorithm: AuthenticateAlgorithm,
        key: [u8; 24],
    ) -> Self {
        let mut d = vec![algorithm as u8, 0x9b, 24];
        d.append(&mut key.to_vec());
        Self {
            cla: 0,
            ins: 0xFF,
            p1: 0xFF,
            p2: touch_policy as u8,
            body: Some(ApduBody {
                data: d,
                rlen: None,
            }),
            response: None,
        }
    }

    /// Get the card serial number
    pub fn get_serial_number(tx: &pcsc::Transaction) -> Result<ApduResponse, pcsc::Error> {
        let mut c = Self {
            cla: 0,
            ins: 0xF8,
            p1: 0,
            p2: 0,
            body: None,
            response: None,
        };
        let stat = c.run_command(tx);
        stat
    }

    /// Run a get metadata command and return parsed results
    pub fn get_metadata(tx: &pcsc::Transaction, slot: u8) -> Result<Metadata, Error> {
        let mut c = Self::new_get_metadata(slot);
        let mut stat = c.run_command(&tx).map_err(|e| Error::PcscError(e))?;
        if let ApduStatus::ResponseBytesRemaining(_d) = stat.status {
            stat.get_full_response(&tx);
        }
        if let ApduStatus::CommandExecutedOk = stat.status {
            let sd = stat.data.ok_or(Error::ExpectedDataMissing)?;
            let mut tlvs = Vec::new();
            let mut index = 0;

            while index < sd.len() {
                let tlv = Tlv::from_vec(&sd[index..]).unwrap();
                index += tlv.len();
                tlvs.push(tlv);
            }

            let mut meta = Metadata {
                algorithm: None,
                pin_policy: None,
                touch_policy: None,
                generated: None,
                public: None,
                default: None,
                retries: None,
            };

            for tlv in tlvs {
                match tlv.tag() {
                    1 => {
                        meta.algorithm = Some(tlv.val().to_vec()[0].into());
                    }
                    2 => {
                        let v = tlv.val().to_vec();
                        meta.pin_policy = Some(v[0].into());
                        meta.touch_policy = Some(v[1].into());
                    }
                    3 => {
                        let v = tlv.val().to_vec()[0];
                        meta.generated = Some(v == 1);
                    }
                    4 => {
                        meta.public = Some(tlv.val().to_vec());
                    }
                    5 => {
                        let v = tlv.val().to_vec()[0];
                        meta.default = Some(v == 1);
                    }
                    6 => {
                        let v = tlv.val().to_vec();
                        meta.retries = Some((v[0], v[1]));
                    }
                    _ => {}
                }
            }
            Ok(meta)
        } else {
            Err(Error::ApduError(stat.status))
        }
    }

    /// Get metadata command
    pub fn new_get_metadata(slot: u8) -> Self {
        Self {
            cla: 0,
            ins: 0xf7,
            p1: 0,
            p2: slot,
            body: None,
            response: None,
        }
    }

    /// Erase the card!
    pub fn new_erase_card() -> Self {
        Self {
            cla: 0,
            ins: 0xfb,
            p1: 0,
            p2: 0,
            body: None,
            response: None,
        }
    }

    /// A new put data command
    pub fn new_put_data(tag: Vec<u8>) -> Self {
        Self {
            cla: 0,
            ins: 0xdb,
            p1: 0x3f,
            p2: 0xff,
            body: Some(ApduBody {
                data: tag,
                rlen: None,
            }),
            response: None,
        }
    }

    /// A command to verify a pin
    pub fn new_verify_pin(pin: &[u8], slot: u8) -> Self {
        let piv_pin = if pin.is_empty() {
            vec![]
        } else {
            let padding = std::iter::repeat(0xff as u8);
            pin.into_iter().map(|a| *a).chain(padding).take(8).collect()
        };
        Self {
            cla: 0,
            ins: 0x20,
            p1: 0,
            p2: slot,
            body: Some(ApduBody {
                data: piv_pin,
                rlen: None,
            }),
            response: None,
        }
    }

    /// A new general authenticate command
    pub fn new_general_authenticate(
        algorithm: AuthenticateAlgorithm,
        slot: Slot,
        tag: &[u8],
    ) -> Self {
        Self {
            cla: 0,
            ins: 0x87,
            p1: algorithm as u8,
            p2: slot as u8,
            body: Some(ApduBody {
                data: tag.to_vec(),
                rlen: None,
            }),
            response: None,
        }
    }

    /// Authenticate to the management key on the card
    pub fn new_authenticate_management1(algorithm: AuthenticateAlgorithm, mutual: bool) -> Self {
        Self {
            cla: 0,
            ins: 0x87,
            p1: algorithm as u8,
            p2: 0x9b,
            body: Some(ApduBody {
                data: vec![0x7c, 0x02, if mutual { 0x80 } else { 0x81 }, 0x00],
                rlen: None,
            }),
            response: None,
        }
    }

    /// Second command to authenticate to the management key on the card (non-mutual authentication)
    pub fn new_authenticate_management2(
        algorithm: AuthenticateAlgorithm,
        challenge: &[u8],
        management_key: &[u8],
    ) -> Self {
        let mut response: [u8; 8] = [0; 8];
        match algorithm {
            AuthenticateAlgorithm::TripleDes => {
                use des::cipher::KeyInit;
                let des = des::TdesEde3::new_from_slice(management_key).unwrap();
                let mut ga = GenericArray::clone_from_slice(challenge);
                des.encrypt_block(&mut ga);
                response.copy_from_slice(&ga[0..8]);
            }
            AuthenticateAlgorithm::Rsa1024 => todo!(),
            AuthenticateAlgorithm::Rsa2048 => todo!(),
            AuthenticateAlgorithm::Aes128 => todo!(),
            AuthenticateAlgorithm::Aes192 => todo!(),
            AuthenticateAlgorithm::EccP256 => todo!(),
            AuthenticateAlgorithm::Aes256 => todo!(),
            AuthenticateAlgorithm::EccP384 => todo!(),
            AuthenticateAlgorithm::CipherSuite2 => todo!(),
            AuthenticateAlgorithm::CipherSuite7 => todo!(),
        }
        let mut d = vec![0x7c, 0x0a, 0x82, response.len() as u8];
        d.append(&mut response.to_vec());
        Self {
            cla: 0,
            ins: 0x87,
            p1: algorithm as u8,
            p2: 0x9b,
            body: Some(ApduBody {
                data: d,
                rlen: None,
            }),
            response: None,
        }
    }

    /// A command to generate an asymmetric key pair
    /// The old key in the slot will be gone forever, be careful.
    /// slot: One of 0x9a, 0x9c, 0x9d, 0x9e, 0x82, 0x93, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0xF9
    /// algorithm: rsa-2048(7)
    ///
    pub fn new_generate_asymmetric_key_pair(
        slot: u8,
        algorithm: AuthenticateAlgorithm,
        pin_policy: KeypairPinPolicy,
        touch_policy: KeypairTouchPolicy,
    ) -> Self {
        Self {
            cla: 0,
            ins: 0x47,
            p1: 0,
            p2: slot,
            body: Some(ApduBody {
                data: vec![
                    0xac,
                    9,
                    0x80,
                    0x01,
                    algorithm as u8,
                    0xaa,
                    0x01,
                    pin_policy as u8,
                    0xab,
                    0x01,
                    touch_policy as u8,
                ],
                rlen: None,
            }),
            response: None,
        }
    }

    /// Convert the apdu command to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        let mut a = vec![self.cla, self.ins, self.p1, self.p2];
        if let Some(body) = &self.body {
            let l = body.data.len() as u16;
            if l == 0 {
            } else if l < 256 {
                a.push(l as u8);
            } else {
                a.push(0);
                let d = l.to_be_bytes();
                a.push(d[0]);
                a.push(d[1]);
            }
            for b in &body.data {
                a.push(*b);
            }
            if let Some(rlen) = body.rlen {
                if rlen > 65536 {
                    panic!("Invalid length data return requested");
                }
                if rlen <= 256 {
                    a.push((rlen & 0xFF) as u8);
                } else {
                    if l <= 255 {
                        a.push(0);
                    }
                    let val: u16 = (rlen & 0xFFFF) as u16;
                    let d = val.to_be_bytes();
                    a.push(d[0]);
                    a.push(d[1]);
                }
            }
        }
        a
    }

    /// Provide the response of the command to the object
    pub fn provide_response(&mut self, r: Vec<u8>) {
        let a: &[u8] = &r;
        self.response = Some(a.into());
    }

    /// Return a reference to the response of the command to the object
    pub fn get_response(&self) -> Option<&ApduResponse> {
        self.response.as_ref()
    }

    /// Run the apdu command with the specified pcsc transaction, returning the response
    pub fn run_command(&mut self, tx: &pcsc::Transaction) -> Result<ApduResponse, pcsc::Error> {
        let mut rbuf: [u8; 2048] = [0; 2048];
        let stat = tx.transmit(&self.to_vec(), &mut rbuf);
        stat.map(|s| s.into())
    }
}

/// Defines the touch policies for a smart card management key
#[repr(u8)]
pub enum ManagementKeyTouchPolicy {
    /// No touch required
    NoTouch = 0xff,
    /// Touch required
    Touch = 0xfe,
    /// Cached touch required
    Cached = 0xfd,
}

/// See table 6.2 of nist 800-78-4
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum AuthenticateAlgorithm {
    /// Triple DES
    TripleDes = 3,
    /// RSA 1024 bit
    Rsa1024 = 6,
    /// RSA 2048 bit
    Rsa2048 = 7,
    /// AES 128 bit
    Aes128 = 8,
    /// AES 192 bit
    Aes192 = 0x10,
    /// ECC P256
    EccP256 = 0x11,
    /// AES 256 bit
    Aes256 = 0x12,
    /// ECC P384
    EccP384 = 0x14,
    /// Used with ecc p256
    CipherSuite2 = 0x27,
    /// Used with ecc p384
    CipherSuite7 = 0x2e,
}

impl From<u8> for AuthenticateAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            0 | 3 => Self::TripleDes,
            6 => Self::Rsa1024,
            7 => Self::Rsa2048,
            8 => Self::Aes128,
            0x10 => Self::Aes192,
            0x11 => Self::EccP256,
            0x12 => Self::Aes256,
            0x14 => Self::EccP384,
            0x27 => Self::CipherSuite2,
            0x2e => Self::CipherSuite7,
            _ => panic!("Invalid algorithm"),
        }
    }
}

/// The policies used for the user needing to enter a pin for smartcard operations
#[derive(Debug)]
#[repr(u8)]
pub enum KeypairPinPolicy {
    /// Default policy
    Default = 0,
    /// Never require a pin
    Never = 1,
    /// Require a pin once
    Once = 2,
    /// Always require a pin
    Always = 3,
}

impl From<u8> for KeypairPinPolicy {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Default,
            1 => Self::Never,
            2 => Self::Once,
            3 => Self::Always,
            _ => panic!("Invalid"),
        }
    }
}

/// The policies used for the user needing to enter a pin for smartcard touch operations
#[derive(Debug)]
#[repr(u8)]
pub enum KeypairTouchPolicy {
    /// Default policy
    Default = 0,
    /// Never require a pin
    Never = 1,
    /// Always require a pin
    Always = 2,
    /// Cached pin
    Cached = 3,
}

impl From<u8> for KeypairTouchPolicy {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Default,
            1 => Self::Never,
            2 => Self::Always,
            3 => Self::Cached,
            _ => panic!("Invalid"),
        }
    }
}

/// The metadata associated with a smartcard
#[derive(Debug)]
pub struct Metadata {
    /// The optional algorithm specified for the smartcard
    pub algorithm: Option<AuthenticateAlgorithm>,
    /// The optional pin policy specified for the smartcard
    pub pin_policy: Option<KeypairPinPolicy>,
    /// The optional touch policy specified for the smartcard
    pub touch_policy: Option<KeypairTouchPolicy>,
    /// Is it generated, otherwise it is imported
    pub generated: Option<bool>,
    /// The optional public key specified for the smartcard
    pub public: Option<Vec<u8>>,
    /// Unsure
    pub default: Option<bool>,
    /// retry count and remaining count
    pub retries: Option<(u8, u8)>,
}

/// An RSA encryption key
#[derive(Debug)]
pub struct AsymmetricRsaKey {
    /// The modulus of the key
    pub modulus: Vec<u8>,
    /// The exponent of the key
    pub exponent: Vec<u8>,
}

/// An assymetric encryption key
#[derive(Debug)]
pub enum AsymmetricKey {
    /// An RSA encryption key
    RsaKey(AsymmetricRsaKey),
}

/// The card capability container data for a smartcard
#[derive(Debug, Default)]
pub struct CardCapabilityContainer {
    /// The id of the card
    id: Option<Vec<u8>>,
    /// The version of the container
    container_version: Option<u8>,
    /// The grammar version of the container
    grammar_version: Option<u8>,
    /// the application card url
    url: Vec<u8>,
    /// pkcs15 data
    pkcs15: Option<Vec<u8>>,
    /// The model number of the registered data
    model: Option<u8>,
    /// access control rule table
    access: Option<Vec<u8>>,
    /// apdus for the card
    apdus: Option<()>,
    /// the redirection tag
    redirection: Option<()>,
    /// capability tuples
    capability_tuples: Option<()>,
    /// Status tuples
    status_tuples: Option<()>,
    /// The next card capability container
    next_ccc: Option<()>,
    /// The extended application URL
    _ext_app_url: Option<Vec<u8>>,
    /// The security object buffer
    _sec_obj_buf: Option<Vec<u8>>,
    /// Error detection code
    err_det_code: Option<()>,
}

impl From<&[u8]> for CardCapabilityContainer {
    fn from(value: &[u8]) -> Self {
        let mut s = Self::default();
        let mut cursor = std::io::Cursor::new(value);
        loop {
            let tag: u8 = cursor.read_le().unwrap();
            let len: u8 = cursor.read_le().unwrap();
            let len = len as usize;
            let mut data = vec![0; len];
            cursor.read_exact(&mut data[0..len]).unwrap();
            match tag {
                0xf0 => {
                    s.id = Some(data);
                }
                0xf1 => {
                    s.container_version = Some(data[0]);
                }
                0xf2 => {
                    s.grammar_version = Some(data[0]);
                }
                0xf3 => {
                    s.url = data;
                }
                0xf4 => {
                    s.pkcs15 = Some(data);
                }
                0xf5 => {
                    s.model = Some(data[0]);
                }
                0xf6 => {
                    s.access = Some(data);
                }
                0xf7 => {
                    s.apdus = Some(());
                }
                0xfa => {
                    s.redirection = Some(());
                }
                0xfb => {
                    s.capability_tuples = Some(());
                }
                0xfc => {
                    s.status_tuples = Some(());
                }
                0xfd => {
                    s.next_ccc = Some(());
                }
                0xfe => {
                    s.err_det_code = Some(());
                    break;
                }
                _ => {
                    panic!("Invalid tag {:02X}", tag);
                }
            }
        }
        s
    }
}

mod piv_card;
pub use piv_card::*;

/// Returns some when there is a card present, otherwise None
pub fn is_card_present() -> Option<String> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("failed to establish context");

    let mut reader_states = vec![
        // Listen for reader insertions/removals, if supported.
        pcsc::ReaderState::new(pcsc::PNP_NOTIFICATION(), pcsc::State::UNAWARE),
    ];
    // Remove dead readers.
    fn is_dead(rs: &pcsc::ReaderState) -> bool {
        rs.event_state()
            .intersects(pcsc::State::UNKNOWN | pcsc::State::IGNORE)
    }
    reader_states.retain(|rs| !is_dead(rs));

    // Add new readers.
    let names = ctx.list_readers_owned().expect("failed to list readers");
    for name in names {
        if !reader_states.iter().any(|rs| rs.name() == name.as_c_str()) {
            reader_states.push(pcsc::ReaderState::new(name, pcsc::State::UNAWARE));
        }
    }

    // Update the view of the state to wait on.
    for rs in &mut reader_states {
        rs.sync_current_state();
    }

    // Wait until the state changes.
    ctx.get_status_change(None, &mut reader_states)
        .expect("failed to get status change");

    // Print current state.
    for rs in &reader_states {
        if rs.event_state().contains(pcsc::State::PRESENT) {
            let reader_name = rs.name();
            let _ = ctx.release();
            return Some(reader_name.to_str().unwrap().to_string());
        }
    }
    None
}

/// Wait until a new card is added to the system, then return the new card
pub async fn wait_for_card(new: bool) -> String {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("failed to establish context");

    let mut reader_states = vec![
        // Listen for reader insertions/removals, if supported.
        pcsc::ReaderState::new(pcsc::PNP_NOTIFICATION(), pcsc::State::UNAWARE),
    ];
    let mut check = !new;
    loop {
        log::debug!("Checking for a piv card");
        // Remove dead readers.
        fn is_dead(rs: &pcsc::ReaderState) -> bool {
            rs.event_state()
                .intersects(pcsc::State::UNKNOWN | pcsc::State::IGNORE)
        }
        reader_states.retain(|rs| !is_dead(rs));

        // Add new readers.
        let names = ctx.list_readers_owned().expect("failed to list readers");
        for name in names {
            if !reader_states.iter().any(|rs| rs.name() == name.as_c_str()) {
                reader_states.push(pcsc::ReaderState::new(name, pcsc::State::UNAWARE));
            }
        }

        // Update the view of the state to wait on.
        for rs in &mut reader_states {
            rs.sync_current_state();
        }

        // Wait until the state changes.
        ctx.get_status_change(None, &mut reader_states)
            .expect("failed to get status change");

        // Print current state.
        for rs in &reader_states {
            log::debug!("Checking reader {:?}: {:?}", rs.name(), rs.event_state());
            if check && rs.name() != pcsc::PNP_NOTIFICATION() {
                if rs.event_state().contains(pcsc::State::PRESENT) {
                    let reader_name = rs.name();
                    let _ = ctx.release();
                    return reader_name.to_str().unwrap().to_string();
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        check = true;
    }
}

/// Convert hash to der format
pub fn rsa_sha256(hash: &[u8]) -> Vec<u8> {
    let mut hash = hash.to_vec();
    // convert to der format, indicating sha-256 hash present
    let mut der_hash = vec![
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    der_hash.append(&mut hash);
    der_hash
}

/// apply pkcs1.5 padding to pkcs1 hash, suitable for signing
pub fn pkcs15_sha256(total_size: usize, hash: &[u8]) -> Vec<u8> {
    // convert to der format, indicating sha-256 hash present
    let mut der_hash = rsa_sha256(hash);

    let plen = total_size - der_hash.len() - 3;
    let mut p = vec![0xff; plen];

    let mut total = Vec::new();
    total.append(&mut vec![0, 1]);
    total.append(&mut p);
    total.push(0);
    total.append(&mut der_hash);
    total
}