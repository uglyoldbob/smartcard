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
        match data {
            None => {
                //writer.erase_card();
                let keypair = writer
                    .generate_keypair(card::Slot::Authentication, card::KeypairPinPolicy::Always);
                writer
                    .reader
                    .piv_pin_auth(vec![b'1', b'2', b'3', b'4', b'5', b'6']);
                let sig = writer.reader.sign_data(vec![0xff; 256]);
                println!("Signature is {:02X?}", sig);
                writer.write_piv_data(vec![0x5f, 0xc1, 5], vec![1, 2, 3, 4, 5]);
            }
            Some(d) => {
                println!("The data read is {:02X?}", d);
            }
        }
    }
}
