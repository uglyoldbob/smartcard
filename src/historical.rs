#[derive(Debug)]
pub enum HistoricalCategory {
    StatusPresent,
    DirReference(u8),
    StatusTlv(Vec<u8>),
    Other(u8),
}

#[derive(Debug)]
pub struct Historical {
    pub category: HistoricalCategory,
}

impl TryFrom<&[u8]> for Historical {
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() > 15 {
            return Err(());
        }
        use omnom::ReadExt;
        use std::io::Read;
        let mut cursor = std::io::Cursor::new(value.to_vec());

        let category: u8 = cursor.read_le().map_err(|_| ())?;
        let his_cat = match category {
            0 => HistoricalCategory::StatusPresent,
            16 => HistoricalCategory::DirReference(cursor.read_le().map_err(|_| ())?),
            0x80 => {
                let mut tlv = Vec::with_capacity(15);
                cursor.read_to_end(&mut tlv).map_err(|_| ())?;
                //TODO parse tlv
                HistoricalCategory::StatusTlv(tlv)
            }
            d if (0x81..=0x8f).contains(&d) => HistoricalCategory::Other(d),
            _ => {
                return Err(());
            }
        };

        Ok(Self { category: his_cat })
    }
}
