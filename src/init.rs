use clap::Parser;
use tlv_parser::tlv::Tlv;

#[derive(Parser, Clone, Debug, clap::ValueEnum)]
enum Mode {
    Initialize,
    SetPrintedInfo,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    mode: Option<Mode>,
}

fn main() {
    let args = Args::parse();

    if let Some(mode) = &args.mode {
        match mode {
            Mode::Initialize => {
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
                        Err(e) => {
                            println!("Error is {:?}, initializing keys", e);
                            init_keys(&mut writer);
                        }
                        Ok(d) => {
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
            }
            Mode::SetPrintedInfo => {
                println!("need to write printed info with example data");
                card::with_current_valid_piv_card(|reader| {
                    let mut writer = reader.to_writer();
                    let e = writer.authenticate_management(card::MANAGEMENT_KEY_DEFAULT);
                    println!("management login {:?}", e);
                    let tlv = Tlv::new(
                        1,
                        tlv_parser::tlv::Value::Val("Example name".as_bytes().to_vec()),
                    )
                    .unwrap();
                    let tlv2 = Tlv::new(
                        2,
                        tlv_parser::tlv::Value::Val("Affiliation example".as_bytes().to_vec()),
                    )
                    .unwrap();
                    let tlv3 = Tlv::new(
                        4,
                        tlv_parser::tlv::Value::Val("202500525".as_bytes().to_vec()),
                    )
                    .unwrap();
                    let tlv4 = Tlv::new(
                        5,
                        tlv_parser::tlv::Value::Val("SERIAL1".as_bytes().to_vec()),
                    )
                    .unwrap();
                    let tlv5 = Tlv::new(
                        6,
                        tlv_parser::tlv::Value::Val("ISSUER_ID".as_bytes().to_vec()),
                    )
                    .unwrap();
                    let tlv6 = Tlv::new(
                        7,
                        tlv_parser::tlv::Value::Val("ORG AFFIL 1".as_bytes().to_vec()),
                    )
                    .unwrap();
                    let tlv7 = Tlv::new(
                        8,
                        tlv_parser::tlv::Value::Val("ORG AFFIL 2".as_bytes().to_vec()),
                    )
                    .unwrap();
                    let tlv8 = Tlv::new(0xfe, tlv_parser::tlv::Value::Nothing).unwrap();
                    let tlv_total = tlv_parser::tlv::Value::TlvList(vec![
                        tlv, tlv2, tlv3, tlv4, tlv5, tlv6, tlv7, tlv8,
                    ]);
                    let s = writer.write_piv_data(vec![0x5f, 0xc1, 0x09], tlv_total.to_vec());
                    println!("Write returned {:02X?}", s);
                });
            }
        }
    }
}
