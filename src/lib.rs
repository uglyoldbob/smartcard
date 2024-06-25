pub mod atr;
pub mod historical;

use des::cipher::{generic_array::GenericArray, BlockEncrypt};
use tlv_parser::tlv::Tlv;

#[derive(Debug)]
pub enum ApduStatus {
    AppletSelectFailed,
    ClassNotSupported,
    CommandExecutedOk,
    CommandNotAllowedNoCurrentEF,
    IncorrectParameter,
    ResponseBytesRemaining(u8),
    SecurityFailed,
    UnknownResponse([u8; 2]),
}

impl From<[u8; 2]> for ApduStatus {
    fn from(value: [u8; 2]) -> Self {
        match (value[0], value[1]) {
            (6, _) => Self::ClassNotSupported,
            (0x61, d) => Self::ResponseBytesRemaining(d),
            (0x69, 0x82) => Self::SecurityFailed,
            (0x69, 0x86) => Self::CommandNotAllowedNoCurrentEF,
            (0x69, 0x99) => Self::AppletSelectFailed,
            (0x6a, 0x80 | 0x86) => Self::IncorrectParameter,
            (0x90, 0x00) => Self::CommandExecutedOk,
            _ => Self::UnknownResponse(value),
        }
    }
}

#[derive(Debug)]
pub struct ApduResponse {
    pub data: Option<Vec<u8>>,
    pub status: ApduStatus,
}

impl ApduResponse {
    /// Process response to authenticate management1 command
    pub fn process_response_authenticate_management1(&self) -> Option<Vec<u8>> {
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

#[derive(Debug)]
pub struct ApduBody {
    data: Vec<u8>,
    /// If Some, represents number of bytes expected.
    rlen: Option<u32>,
}

#[derive(Debug)]
pub struct ApduCommand {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    body: Option<ApduBody>,
    response: Option<ApduResponse>,
}

impl ApduCommand {
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

    pub fn new_select_file_id(f: Vec<u8>) -> Self {
        Self {
            cla: 0,
            ins: 0xa4,
            p1: 0,
            p2: 0,
            body: Some(ApduBody {
                data: f,
                rlen: None,
            }),
            response: None,
        }
    }

    /// Does not work?
    pub fn new_select() -> Self {
        Self {
            cla: 0,
            ins: 0xa4,
            p1: 0,
            p2: 0,
            body: Some(ApduBody {
                data: vec![0x3f, 0],
                rlen: None,
            }),
            response: None,
        }
    }

    /// Set the management key
    pub fn new_set_management_key(
        touch_policy: ManagementKeyTouchPoliicy,
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

    /// Run a get metadata command and return parsed results
    pub fn get_metadata(tx: &pcsc::Transaction, slot: u8) -> Option<Metadata> {
        let mut c = Self::new_get_metadata(slot);
        let stat = c.run_command(&tx);
        println!("Status of get metadata is {:02x?}", stat);
        if let Some(s) = stat {
            let sd = s.data.unwrap();
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
                println!("Tlv data parsed is {} {}", tlv.len(), tlv.to_string());
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
            Some(meta)
        } else {
            None
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
    /// slot: One of 0x9a, 0x9c, 0x9d, 0x9e, 0x82, 0x93, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0xF9
    /// algorithm: rsa-2048(7)
    ///
    pub fn new_generate_asymmetric_key_pair(
        slot: u8,
        algorithm: u8,
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
                    algorithm,
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

    pub fn to_vec(&self) -> Vec<u8> {
        let mut a = vec![self.cla, self.ins, self.p1, self.p2];
        if let Some(body) = &self.body {
            let l = body.data.len() as u16;
            if l == 0 {
            } else if l < 256 {
                a.push(l as u8);
            } else {
                a.push(0);
                let d = l.to_le_bytes();
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
                    let d = val.to_le_bytes();
                    a.push(d[0]);
                    a.push(d[1]);
                }
            }
        }
        a
    }

    pub fn provide_response(&mut self, r: Vec<u8>) {
        let a: &[u8] = &r;
        self.response = Some(a.into());
    }

    pub fn get_response(&self) -> Option<&ApduResponse> {
        self.response.as_ref()
    }

    pub fn run_command(&mut self, tx: &pcsc::Transaction) -> Option<ApduResponse> {
        println!("Command is {:02X?}", self.to_vec());
        let mut rbuf: [u8; 256] = [0; 256];
        let stat = tx.transmit(&self.to_vec(), &mut rbuf);
        stat.ok().map(|s| s.into())
    }
}

#[repr(u8)]
pub enum ManagementKeyTouchPoliicy {
    NoTouch = 0xff,
    Touch = 0xfe,
    Cached = 0xfd,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum AuthenticateAlgorithm {
    TripleDes = 3,
    Rsa1024 = 6,
    Rsa2048 = 7,
    Aes128 = 8,
    Aes192 = 10,
    EccP256 = 11,
    Aes256 = 12,
    EccP384 = 14,
}

impl From<u8> for AuthenticateAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            3 => Self::TripleDes,
            6 => Self::Rsa1024,
            7 => Self::Rsa2048,
            8 => Self::Aes128,
            10 => Self::Aes192,
            11 => Self::EccP256,
            12 => Self::Aes256,
            14 => Self::EccP384,
            _ => panic!("Invalid algorithm"),
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum KeypairPinPolicy {
    Default = 0,
    Never = 1,
    Once = 2,
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

#[derive(Debug)]
#[repr(u8)]
pub enum KeypairTouchPolicy {
    Default = 0,
    Never = 1,
    Always = 2,
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

#[derive(Debug)]
pub struct Metadata {
    pub algorithm: Option<AuthenticateAlgorithm>,
    pub pin_policy: Option<KeypairPinPolicy>,
    pub touch_policy: Option<KeypairTouchPolicy>,
    /// Is it generated, otherwise it is imported
    pub generated: Option<bool>,
    pub public: Option<Vec<u8>>,
    pub default: Option<bool>,
    /// retry count and remaining count
    pub retries: Option<(u8, u8)>,
}
