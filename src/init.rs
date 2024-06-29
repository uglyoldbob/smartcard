fn main() {
    card::with_next_valid_piv_card(|reader| {
        let mut writer = card::PivCardWriter::extend(reader);
        let data = writer.reader.get_piv_data(vec![0x5f, 0xc1, 5]);
        println!("Data read is {:02X?}", data);
        let init_keys = |writer: &mut card::PivCardWriter| {
            let _keypair = writer
                .generate_keypair_with_management(
                    card::MANAGEMENT_KEY_DEFAULT,
                    card::AuthenticateAlgorithm::Rsa2048,
                    card::Slot::Authentication,
                    card::KeypairPinPolicy::Always,
                )
                .unwrap();
            let keypair2 = writer.generate_keypair_with_management(
                card::MANAGEMENT_KEY_DEFAULT,
                card::AuthenticateAlgorithm::Rsa2048,
                card::Slot::Signing,
                card::KeypairPinPolicy::Always,
            );
            println!("Keypair2 is {:?}", keypair2);
            if keypair2.is_err() {
                return;
            }
        };
        match data {
            None => {
                init_keys(&mut writer);
            }
            Some(d) => {
                println!("The data read is {:02X?}", d);
                let sig = writer.reader.sign_data(
                    card::Slot::Authentication,
                    &[b'1', b'2', b'3', b'4', b'5', b'6'],
                    vec![0xff; 256],
                );
                let sig2 = writer.reader.sign_data(
                    card::Slot::Signing,
                    &[b'1', b'2', b'3', b'4', b'5', b'6'],
                    vec![0xff; 256],
                );
                println!("Signature is {:02X?}", sig);
                println!("Signature2 is {:02X?}", sig2);
            }
        }
    });
    card::with_current_valid_piv_card(|reader| {
        let mut writer = card::PivCardWriter::extend(reader);
        if true {
            writer
                .maybe_store_x509_cert(card::MANAGEMENT_KEY_DEFAULT, &[1, 2, 3, 4, 5], 1)
                .expect("Failed to write dummy certificate");
        }
    });
}
