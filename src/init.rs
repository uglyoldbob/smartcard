fn main() {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("failed to establish context");
    let names = ctx.list_readers_owned().expect("failed to list readers");
    for name in names {
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

        let mut writer = card::PivCardWriter::new(&mut card);
        writer.reader.bruteforce_aid();

        let data = writer.reader.get_piv_data(vec![0x5f, 0xc1, 5]);
        println!("Data read is {:02X?}", data);
        let init_keys = |writer: &mut card::PivCardWriter| {
            let keypair = writer.generate_keypair(
                card::AuthenticateAlgorithm::Rsa2048,
                card::Slot::Authentication,
                card::KeypairPinPolicy::Always,
            );
            let keypair2 = writer.generate_keypair(
                card::AuthenticateAlgorithm::Rsa2048,
                card::Slot::Signing,
                card::KeypairPinPolicy::Always,
            );
            let sig = writer.reader.sign_data(
                card::Slot::Authentication,
                vec![b'1', b'2', b'3', b'4', b'5', b'6'],
                vec![0xff; 255],
            );
            let sig2 = writer.reader.sign_data(
                card::Slot::Signing,
                vec![b'1', b'2', b'3', b'4', b'5', b'6'],
                vec![0xff; 255],
            );
            println!("Signature is {:02X?}", sig);
            println!("Signature2 is {:02X?}", sig2);
            writer.write_piv_data(vec![0x5f, 0xc1, 5], vec![1, 2, 3, 4, 5]);
        };
        match data {
            None => {
                init_keys(&mut writer);
            }
            Some(d) => {
                println!("The data read is {:02X?}", d);
            }
        }
    }
}
