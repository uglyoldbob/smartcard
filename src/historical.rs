//! Historical bytes of the ATR.

/// The category of the historical bytes.
#[derive(Debug)]
pub enum HistoricalCategory {
    /// The status is present
    StatusPresent,
    /// A directory reference in the card
    DirReference(u8),
    /// The tlv status of the card
    StatusTlv(Vec<u8>),
    /// Some other historical data
    Other(u8),
}

/// The historical bytes of an ATR.
#[derive(Debug)]
pub struct Historical {
    /// The category of the historical bytes.
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
