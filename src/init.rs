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

        let mut writer = card::PivCardWriter::new(&mut card);
        writer.reader.bruteforce_aid();

        //writer.erase_card();
        let keypair =
            writer.generate_keypair(card::Slot::Authentication, card::KeypairPinPolicy::Always);
    }
}
