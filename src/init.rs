use card::ApduStatus;

fn main() {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("failed to establish context");
    let names = ctx.list_readers_owned().expect("failed to list readers");
    for name in names {
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

        let tx = card.transaction().map_err(|_| ()).unwrap();

        if false {
            let mut erase = card::ApduCommand::new_erase_card();
            let erases = erase.run_command(&tx);
            println!("Response of erase is {:02X?}", erases);
        }

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
            let stat = c.run_command(&tx);
            println!("Status of select file {} is {:02x?}", i, stat);
        }

        {
            let md = card::ApduCommand::get_metadata(&tx, 0x9b).unwrap();
            println!("Metadata is {:02x?}", md);

            let algorithm = md
                .algorithm
                .clone()
                .unwrap_or_else(|| card::AuthenticateAlgorithm::Rsa2048);

            let mut c = card::ApduCommand::new_authenticate_management1(algorithm, false);
            let stat = c.run_command(&tx).unwrap();
            println!("Status of authenticate1 is {:02x?}", stat);
            if let ApduStatus::CommandExecutedOk = stat.status {
                let challenge = stat.process_response_authenticate_management1();
                println!("Need to finish authentication now with {:02X?}", challenge);
                let mut c2 = card::ApduCommand::new_authenticate_management2(
                    algorithm,
                    challenge.as_ref().unwrap(),
                    &[
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
                        0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    ],
                );
                let stat2 = c2.run_command(&tx);
                println!("Response of auth2 is {:02X?}", stat2);
                if let ApduStatus::CommandExecutedOk = stat2.as_ref().unwrap().status {
                    println!("Success auth2");
                } else {
                    println!("NOT success auth2");
                }
            } else if let ApduStatus::IncorrectParameter = stat.status {
                println!("Need to initialize management key?");
                let mut c = card::ApduCommand::new_set_management_key(
                    card::ManagementKeyTouchPolicy::NoTouch,
                    md.algorithm
                        .unwrap_or_else(|| card::AuthenticateAlgorithm::Rsa2048),
                    [42; 24],
                );
                let stat = c.run_command(&tx);
                println!("Status of set management key is {:02x?}", stat);
            }
        }

        let mut c = card::ApduCommand::new_generate_asymmetric_key_pair(
            0x9a,
            card::AuthenticateAlgorithm::Rsa2048,
            card::KeypairPinPolicy::Always,
            card::KeypairTouchPolicy::Never,
        );
        let stat = c.run_command(&tx);
        if let Ok(mut r) = stat {
            r.get_full_response(&tx);
            println!("The response of generate key is {:02X?}", r.status);
            let d = r.data.as_ref().unwrap();
            println!("The full data is {} bytes {:02X?}", d.len(), d);
            let key = r.parse_asymmetric_key_response(card::AuthenticateAlgorithm::Rsa2048);
            println!("The key is {:02X?}", key);
        }

        let serial = card::ApduCommand::get_serial_number(&tx);
        println!("Serial is {:02X?}", serial);

        tx.end(pcsc::Disposition::LeaveCard)
            .map_err(|(_, _err)| ())
            .unwrap();
    }
}
