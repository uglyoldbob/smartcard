fn parse_card(card: &mut pcsc::Card) -> Result<(), ()> {
    // Start an exclusive transaction (not required -- can work on card directly).
    let tx = card
        .transaction()
        .expect("failed to begin card transaction");

    // Get the card status.
    let (names_len, _atr_len) = tx.status2_len().expect("failed to get the status length");
    let mut names_buf = vec![0; names_len];
    let mut atr_buf = [0; pcsc::MAX_ATR_SIZE];
    let status = tx
        .status2(&mut names_buf, &mut atr_buf)
        .expect("failed to get card status");
    println!("Status from status: {:?}", status.status());
    println!(
        "Reader names from status: {:?}",
        status.reader_names().collect::<Vec<_>>()
    );
    if let Some(protocol) = status.protocol2() {
        println!("Protocol from status: {:?}", protocol);
    } else {
        println!("Protocol from status: directly connected");
    }
    println!("ATR from status: {:02X?}", status.atr());

    let atr: Atr = status.atr().into();

    println!("ATR from status IS {:02X?}", atr);
    if let Some(hist) = &atr.historical {
        let hist: &[u8] = hist;
        if let Ok(h) = hist.try_into() {
            let h: Historical = h;
            println!("historical data is {:02X?}", h);
        }
    }

    // Send some harmless APDU to the card.
    if let Some(_) = status.protocol2() {
        let apdu = b"\x00\xa4\x04\x00\x08\x31\x54\x49\x43\x2e\x49\x43\x41";
        let mut rapdu_buf = [0; pcsc::MAX_BUFFER_SIZE];
        let rapdu = tx
            .transmit(apdu, &mut rapdu_buf)
            .expect("failed to transmit APDU to card");
        println!("RAPDU: {:?}", rapdu);
    }

    // Get the card's ATR.
    let mut atr_buf = [0; pcsc::MAX_ATR_SIZE];
    if let Ok(atr) = tx.get_attribute(pcsc::Attribute::AtrString, &mut atr_buf) {
        println!("ATR from attribute: {:02X?}", atr);
    } else {
        println!("Did not get ATR");
    }

    let atr: Atr = atr.into();
    println!("ATR from attribute IS {:02X?}", atr);
    if let Some(hist) = &atr.historical {
        let hist: &[u8] = hist;
        if let Ok(h) = hist.try_into() {
            let h: Historical = h;
            println!("historical data is {:02X?}", h);
        }
    }

    // Get some attribute.
    let mut ifd_version_buf = [0; 4];
    if let Ok(ifd_version) =
        tx.get_attribute(pcsc::Attribute::VendorIfdVersion, &mut ifd_version_buf)
    {
        println!("Vendor IFD version: {:?}", ifd_version);
    } else {
        println!("Did not get IFD version");
    }

    // Get some other attribute.
    // This time we allocate a buffer of the needed length.
    if let Ok(vendor_name_len) = tx.get_attribute_len(pcsc::Attribute::VendorName) {
        let mut vendor_name_buf = vec![0; vendor_name_len];
        if let Ok(vendor_name) = tx.get_attribute(pcsc::Attribute::VendorName, &mut vendor_name_buf)
        {
            println!("Vendor name: {}", std::str::from_utf8(vendor_name).unwrap());
        } else {
            println!("failed to get vendor name attribute");
        }
    } else {
        println!("failed to get the vendor name attribute length");
    }

    // Can either end explicity, which allows error handling,
    // and setting the disposition method, or leave it to drop, which
    // swallows any error and hardcodes LeaveCard.
    tx.end(pcsc::Disposition::LeaveCard)
        .map_err(|(_, err)| err)
        .expect("failed to end transaction");
    Ok(())
}

mod atr;
use atr::Atr;
mod historical;
use historical::Historical;

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

fn sign_something(card: &mut pcsc::Card) -> Result<Vec<u8>, ()> {
    let tx = card.transaction().map_err(|_| ())?;

    let aids = vec![
        vec![0x31, 0x54, 0x49, 0x43, 0x2E, 0x49, 0x43, 0x41],
        vec![0x62, 0x76, 0x01, 0xFF, 0x00, 0x00, 0x00],
        vec![0xa0, 0x00, 0x00, 0x00, 0x01, 0x01],
        vec![
            0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01,
        ],
        vec![
            0xD2, 0x33, 0x00, 0x00, 0x00, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x33,
            0x35,
        ],
        vec![
            0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
        ],
    ];
    for (i, aid) in aids.iter().enumerate() {
        let mut c = ApduCommand::SelectFile(SelectFile::new_aid(aid.to_owned()));
        let mut rbuf: [u8; 256] = [0; 256];
        println!("Command {} is {:02X?}", i, c.to_vec());
        let stat = tx.transmit(&c.to_vec(), &mut rbuf);
        if let Ok(r) = stat {
            c.provide_response(r.to_vec());
            let r = c.get_response();
            println!("The response is {:02X?}", c.get_response());
        }
        println!("Status of select file is {:02x?}", stat);
    }
    let d = vec![0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

    tx.end(pcsc::Disposition::LeaveCard)
        .map_err(|(_, _err)| ())?;
    Err(())
}

fn main() {
    // Get a context.
    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("failed to establish context");

    // Instead of manually allocating the buffer for the reader names, we let pcsc take care of
    // that
    let names = ctx.list_readers_owned().expect("failed to list readers");
    for name in names {
        println!("{:?}", name);

        let card = ctx.connect(&name, pcsc::ShareMode::Shared, pcsc::Protocols::ANY);
        if let Err(e) = card {
            println!(
                "Failed to connect to {}: {}",
                name.into_string().unwrap(),
                e
            );
            continue;
        }
        let mut card = card.unwrap();

        parse_card(&mut card);
        sign_something(&mut card);
    }

    ctx.release()
        .map_err(|(_, err)| err)
        .expect("failed to release context");
}
