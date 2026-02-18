#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zk_cred_longfellow::{
    Codec,
    circuit::Circuit,
    fields::{field2_128::Field2_128, fieldp128::FieldP128, fieldp256::FieldP256},
};

fuzz_target!(|data: &[u8]| fuzz(data));

fn fuzz(data: &[u8]) {
    let mut cursor = Cursor::new(data);
    let _ = Circuit::<FieldP128>::decode(&mut cursor);
    let mut cursor = Cursor::new(data);
    let _ = Circuit::<Field2_128>::decode(&mut cursor);
    let mut cursor = Cursor::new(data);
    let _ = Circuit::<FieldP256>::decode(&mut cursor);
}
