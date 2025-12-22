mod layout;

/// Versions of the mdoc_zk circuit interface.
pub enum CircuitVersion {
    V6 = 6,
}

#[cfg(test)]
pub(super) mod tests {
    use crate::{Codec, circuit::Circuit};
    use std::io::Cursor;

    pub(super) fn load_circuits(attributes: u8) -> (Circuit, Circuit) {
        let data = match attributes {
            1 => include_bytes!("../../test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6").as_slice(),
            2 => include_bytes!("../../test-vectors/mdoc_zk/6_2_b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e").as_slice(),
            3 => include_bytes!("../../test-vectors/mdoc_zk/6_3_b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010").as_slice(),
            4 => include_bytes!("../../test-vectors/mdoc_zk/6_4_c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6").as_slice(),
            _ => panic!("unsupported number of attributes"),
        };
        let decompressed = zstd::decode_all(data).unwrap();
        let mut cursor = Cursor::new(decompressed.as_slice());
        let first_circuit = Circuit::decode(&mut cursor).unwrap();
        let second_circuit = Circuit::decode(&mut cursor).unwrap();
        assert_eq!(
            cursor.position(),
            u64::try_from(decompressed.len()).unwrap(),
            "extra data"
        );
        (first_circuit, second_circuit)
    }
}
