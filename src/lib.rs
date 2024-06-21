pub mod atr;
pub mod historical;

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

#[repr(u8)]
pub enum AuthenticateAlgorithm {
    Rsa1024 = 6,
    Rsa2048 = 7,
    Aes128 = 8,
    Aes192 = 10,
    EccP256 = 11,
    Aes256 = 12,
    EccP384 = 14,
}

#[repr(u8)]
pub enum KeypairPinPolicy {
    Never = 1,
    Once = 2,
    Always = 3,
}

#[repr(u8)]
pub enum KeypairTouchPolicy {
    Never = 1,
    Always = 2,
    Cached = 3,
}
