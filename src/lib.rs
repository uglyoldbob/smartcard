pub mod atr;
pub mod historical;

#[derive(Debug)]
pub enum ApduStatus {
    ClassNotSupported,
    CommandExecutedOk,
    ResponseBytesRemaining(u8),
    CommandNotAllowedNoCurrentEF,
    AppletSelectFailed,
    UnknownResponse([u8; 2]),
}

impl From<[u8; 2]> for ApduStatus {
    fn from(value: [u8; 2]) -> Self {
        match (value[0], value[1]) {
            (6, _) => Self::ClassNotSupported,
            (0x61, d) => Self::ResponseBytesRemaining(d),
            (0x69, 0x86) => Self::CommandNotAllowedNoCurrentEF,
            (0x69, 0x99) => Self::AppletSelectFailed,
            (0x90, 0x00) => Self::CommandExecutedOk,
            _ => Self::UnknownResponse(value),
        }
    }
}

#[derive(Debug)]
pub struct ApduResponse {
    data: Option<Vec<u8>>,
    status: ApduStatus,
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

#[enum_dispatch::enum_dispatch]
pub trait ApduCommandTrait {
    fn to_vec(&self) -> Vec<u8>;
    fn provide_response(&mut self, r: Vec<u8>);
    fn get_response(&self) -> Option<&ApduResponse>;
}

#[derive(Debug)]
pub struct GenericApduBody {
    data: Vec<u8>,
    /// If Some, represents number of bytes expected.
    rlen: Option<u32>,
}

#[derive(Debug)]
pub struct GenericApduCommand {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    body: Option<GenericApduBody>,
    response: Option<ApduResponse>,
}

impl ApduCommandTrait for GenericApduCommand {
    fn to_vec(&self) -> Vec<u8> {
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

    fn provide_response(&mut self, r: Vec<u8>) {
        let a: &[u8] = &r;
        self.response = Some(a.into());
    }

    fn get_response(&self) -> Option<&ApduResponse> {
        self.response.as_ref()
    }
}

#[derive(Debug)]
pub struct SelectFile {
    cmd: GenericApduCommand,
}

impl SelectFile {
    pub fn new_aid(f: Vec<u8>) -> Self {
        Self {
            cmd: GenericApduCommand {
                cla: 0,
                ins: 0xa4,
                p1: 4,
                p2: 0,
                body: Some(GenericApduBody {
                    data: f,
                    rlen: None,
                }),
                response: None,
            },
        }
    }

    pub fn new_file_id(f: Vec<u8>) -> Self {
        Self {
            cmd: GenericApduCommand {
                cla: 0,
                ins: 0xa4,
                p1: 0,
                p2: 0,
                body: Some(GenericApduBody {
                    data: f,
                    rlen: None,
                }),
                response: None,
            },
        }
    }

    /// Does not work?
    pub fn new() -> Self {
        Self {
            cmd: GenericApduCommand {
                cla: 0,
                ins: 0xa4,
                p1: 0,
                p2: 0,
                body: Some(GenericApduBody {
                    data: vec![0x3f, 0],
                    rlen: None,
                }),
                response: None,
            },
        }
    }
}

impl ApduCommandTrait for SelectFile {
    fn to_vec(&self) -> Vec<u8> {
        self.cmd.to_vec()
    }

    fn provide_response(&mut self, r: Vec<u8>) {
        self.cmd.provide_response(r);
    }

    fn get_response(&self) -> Option<&ApduResponse> {
        self.cmd.get_response()
    }
}

#[derive(Debug)]
#[enum_dispatch::enum_dispatch(ApduCommandTrait)]
pub enum ApduCommand {
    SelectFile(SelectFile),
    Generic(GenericApduCommand),
}
