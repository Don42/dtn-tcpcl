extern crate dtn_tcpcl;

use std::io::{self, Write};

fn main(){
    let mut header = dtn_tcpcl::ContactHeader::new();
    header.flags(dtn_tcpcl::CAN_TLS).eid("localhost").unwrap();
    let buffer = header.serialize();
    io::stdout().write(buffer.as_slice()).unwrap();
}