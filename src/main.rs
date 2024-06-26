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
        reader.bruteforce_aid().unwrap();
        reader.get_ccc().unwrap();
        let cert = reader.get_x509_cert();
        println!("Cert is {:02X?}", cert);

        let public_key = reader.get_public_key(card::Slot::Authentication);
        println!("The public key is {:02X?}", public_key);
        let der = public_key.map(|p| p.to_der());
        println!("DER ENCODING IS {:02X?}", der);

        let data = reader.get_piv_data(vec![0x5f, 0xc1, 5]);
        println!("Data read is {:02X?}", data);

        let sig = reader.sign_data(
            card::Slot::Authentication,
            vec![b'1', b'2', b'3', b'4', b'5', b'6'],
            vec![0xff; 255],
        );
        println!("Signature is {:02X?}", sig);
    }

    ctx.release()
        .map_err(|(_, err)| err)
        .expect("failed to release context");
}
