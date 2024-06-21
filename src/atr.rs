#[derive(Debug)]
pub struct Atr {
    pub direct: bool,
    pub historical: Option<Vec<u8>>,
    ///ta1 is accessed with t[0][0]
    ///tb1 is accessed with t[0][1]
    ///tc1 is accessed with t[0][2]
    ///ta2 is accessed with t[1][0]
    pub t: Vec<[Option<u8>; 4]>,
    pub sum: u8,
    pub tck: Option<u8>,
    pub future: Vec<u8>,
}

impl Atr {
    pub fn clocks_per_etu(&self) -> Option<f32> {
        let (di, fi) = if let Some(ta1) = self.t[0][0] {
            let di = match ta1 & 0xF {
                d if (1..=7).contains(&d) => Some(1 << d),
                8 => Some(12),
                9 => Some(20),
                _ => None,
            };
            let fi = match ta1 >> 4 {
                0 | 1 => Some(372),
                2 => Some(558),
                3 => Some(744),
                4 => Some(1116),
                5 => Some(1488),
                6 => Some(1860),
                9 => Some(512),
                10 => Some(768),
                11 => Some(1024),
                12 => Some(1536),
                13 => Some(2048),
                _ => None,
            };
            (di, fi)
        } else {
            (Some(1), Some(372))
        };
        fi.and_then(|fi| di.map(|di| fi as f32 / di as f32))
    }

    /// Returns the max frequency in hertz
    pub fn max_frequency(&self) -> Option<f64> {
        if let Some(ta1) = self.t[0][0] {
            match ta1 >> 4 {
                0 => Some(4.0e6),
                1 | 9 => Some(5.0e6),
                2 => Some(6.0e6),
                3 => Some(8.0e6),
                4 => Some(12.0e6),
                5 => Some(16.0e6),
                6 | 13 => Some(20.0e6),
                10 => Some(7.5e6),
                11 => Some(10.0e6),
                12 => Some(15.0e6),
                _ => None,
            }
        } else {
            None
        }
    }
}

impl From<&[u8]> for Atr {
    fn from(value: &[u8]) -> Self {
        use omnom::ReadExt;
        use std::io::Read;
        let mut cursor = std::io::Cursor::new(value.to_vec());
        let direct: u8 = cursor.read_le().unwrap();

        let mut have_tck = false;

        let t0: u8 = cursor.read_le().unwrap();

        let mut t = Vec::new();

        let mut tn = Some(t0);

        loop {
            if let Some(tn2) = tn {
                if (tn2 & 0xF0) != 0 {
                    let tabcd: Vec<Option<u8>> = (4..8)
                        .into_iter()
                        .map(|i| {
                            if (t0 & (1 << i)) != 0 {
                                cursor.read_le().ok()
                            } else {
                                None
                            }
                        })
                        .collect();
                    if let Some(d) = tabcd[3] {
                        if d != 0 {
                            have_tck = true;
                        }
                    }
                    let mut tabcd2 = [None; 4];
                    tabcd2.copy_from_slice(&tabcd[0..4]);
                    tn = tabcd[3];
                    t.push(tabcd2);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        let historical_len = (t0 & 0xF) as usize;
        let historical = if historical_len > 0 {
            let mut historical = vec![0; historical_len];
            cursor
                .read_exact(&mut historical[0..historical_len])
                .unwrap();
            Some(historical)
        } else {
            None
        };

        let mut remaining = Vec::new();
        cursor.read_to_end(&mut remaining).unwrap();

        let len: usize = cursor.position() as usize;
        let tck = if have_tck {
            Some(cursor.read_le().unwrap())
        } else {
            None
        };
        let sum = value[0..len].iter().fold(0, |a, b| a ^ b);

        Self {
            direct: direct == 0x3b,
            historical,
            t,
            sum,
            tck,
            future: remaining,
        }
    }
}
