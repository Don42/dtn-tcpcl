extern crate dtn_tcpcl;

use std::io::{self, Read};

fn main() {
    let mut buffer: Vec<u8> = Vec::with_capacity(32);
    io::stdin().read_to_end(&mut buffer).unwrap();
    let (_, header) = dtn_tcpcl::ContactHeader::deserialize(buffer.as_slice()).unwrap();
    println!("{:?}", header);
}
