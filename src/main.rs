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
    println!("ATR from status: {:?}", status.atr());

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
        println!("ATR from attribute: {:?}", atr);
    } else {
        println!("Did not get ATR");
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
    }

    ctx.release()
        .map_err(|(_, err)| err)
        .expect("failed to release context");
}
