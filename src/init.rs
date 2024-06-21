use card::{ApduResponse, ApduStatus};
use tlv_parser::tlv::{Tlv, Value};

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
        let mut rbuf: [u8; 256] = [0; 256];

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

            let mut c = card::ApduCommand::new_authenticate_management1(
                md.algorithm
                    .clone()
                    .unwrap_or_else(|| card::AuthenticateAlgorithm::Rsa2048),
                false,
            );
            let stat = c.run_command(&tx).unwrap();
            println!("Status of authenticate1 is {:02x?}", stat);
            if let ApduStatus::CommandExecutedOk = stat.status {
                println!("Need to finish authentication now");
            } else if let ApduStatus::IncorrectParameter = stat.status {
                println!("Need to initialize management key?");
                let mut c = card::ApduCommand::new_set_management_key(
                    card::ManagementKeyTouchPoliicy::Touch,
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
            7,
            card::KeypairPinPolicy::Always,
            card::KeypairTouchPolicy::Always,
        );
        println!("Command is {:02X?}", c.to_vec());
        let stat = tx.transmit(&c.to_vec(), &mut rbuf);
        if let Ok(r) = stat {
            c.provide_response(r.to_vec());
            let r = c.get_response();
            println!("The response of generate key is {:02X?}", c.get_response());
        }
        println!("Status of generate key is {:02x?}", stat);

        tx.end(pcsc::Disposition::LeaveCard)
            .map_err(|(_, _err)| ())
            .unwrap();
    }
}
