use card::*;
use tlv_parser::tlv;
use tlv_parser::tlv::Tlv;
use tlv_parser::tlv::Value;

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

    let atr: card::atr::Atr = status.atr().into();

    println!("ATR from status IS {:02X?}", atr);
    if let Some(hist) = &atr.historical {
        let hist: &[u8] = hist;
        if let Ok(h) = hist.try_into() {
            let h: card::historical::Historical = h;
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

    let atr: card::atr::Atr = atr.into();
    println!("ATR from attribute IS {:02X?}", atr);
    if let Some(hist) = &atr.historical {
        let hist: &[u8] = hist;
        if let Ok(h) = hist.try_into() {
            let h: card::historical::Historical = h;
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

    let serial = card::ApduCommand::get_serial_number(&tx);
    println!("Serial is {:02X?}", serial);

    {
        let tlv = tlv_parser::tlv::Tlv::new(0x5c, tlv_parser::tlv::Value::Val(vec![0x7e])).unwrap();
        let mut c = card::ApduCommand::new_get_data(tlv.to_vec());
        let r = c.run_command(&tx);
        if let Ok(r) = &r {
            if let Some(d) = &r.data {
                let tlv = tlv::Tlv::from_vec(d).unwrap();
                println!("TLV IS {}", tlv);
            }
        }
        println!("Response of get data2 is {:02X?}", r);
    }

    {
        let tlv =
            tlv_parser::tlv::Tlv::new(0x5c, tlv_parser::tlv::Value::Val(vec![0x5f, 0xc1, 0x05]))
                .unwrap();
        let mut c = card::ApduCommand::new_get_data(tlv.to_vec());
        let r = c.run_command(&tx);
        if let Ok(r) = &r {
            if let Some(d) = &r.data {
                let tlv = tlv::Tlv::from_vec(d).unwrap();
                println!("Tlv of x509 cert is {}", tlv);
            } else {
                println!("Total response is {:02X?}", r);
            }
        } else {
            println!("Error for get x509 cert is {:?}", r.err());
        }
    }

    // Can either end explicity, which allows error handling,
    // and setting the disposition method, or leave it to drop, which
    // swallows any error and hardcodes LeaveCard.
    tx.end(pcsc::Disposition::LeaveCard)
        .map_err(|(_, err)| err)
        .expect("failed to end transaction");
    Ok(())
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
        let mut c = card::ApduCommand::new_select_aid(aid.to_owned());
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

        let card = ctx.connect(&name, pcsc::ShareMode::Exclusive, pcsc::Protocols::ANY);
        if let Err(e) = card {
            println!(
                "Failed to connect to {}: {}",
                name.into_string().unwrap(),
                e
            );
            continue;
        }
        let mut card = card.unwrap();

        let mut reader = card::PivCardReader::new(&mut card);
        reader.bruteforce_aid();
        reader.get_ccc();
        let cert = reader.get_x509_cert();
        println!("Cert is {:02X?}", cert);

        let data = reader.get_piv_data(vec![0x5f, 0xc1, 5]);
        println!("Data read is {:02X?}", data);

        reader.piv_pin_auth(vec![b'1', b'2', b'3', b'4', b'5', b'6']);
        reader.piv_pin_auth(vec![]);
        let sig = reader.sign_data(vec![0xff; 256]);
        println!("Signature is {:02X?}", sig);
    }

    ctx.release()
        .map_err(|(_, err)| err)
        .expect("failed to release context");
}
