use tlv_parser::tlv::Value;

fn main() {
    let mut public_key = Vec::new();
    card::with_current_valid_piv_card(|reader| {
        if let Ok(p) = reader.get_public_key(card::Slot::Authentication) {
            public_key = p.to_der();
        }
        println!("The public key is {:02X?}", public_key);

        let cert = reader.get_x509_cert(1);
        println!("Cert is {:02X?}", cert);

        let disc = reader.read_discovery();
        println!("Disc is {:02X?}", disc);
    });

    // For now, copy what is generated from the initialize program, (the der output).
    card::with_piv_and_public_key(
        &public_key,
        |mut reader| {
            println!("Got a card with the public key we wanted");
            let cert = reader.get_x509_cert(1);
            println!("Cert is {:02X?}", cert);
            let e = reader.piv_pin_auth(card::PIV_PIN_KEY_DEFAULT);
            println!("Pin login {:?}", e);
            let d = reader.get_piv_data(vec![0x5f, 0xc1, 9]);
            println!("Printed info is {:?}", d);
        },
        std::time::Duration::from_secs(10),
    )
    .expect("Failed to operate on card with public key");
}
