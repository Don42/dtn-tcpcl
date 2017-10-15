extern crate dtn_tcpcl;
extern crate nom;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use nom::IResult;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:4556").unwrap();
    eprintln!("Listening on {}", listener.local_addr().unwrap());

    for stream in listener.incoming() {
        match stream {
            Err(_) => println!("error listen"),
            Ok(mut stream) => {
                println!("DEBUG: got connection from {} to {}",
                         stream.peer_addr().unwrap(),
                         stream.local_addr().unwrap());
                std::thread::spawn(move || {
                    handle_connection(stream);
                });
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream) {
    let mut header = dtn_tcpcl::ContactHeader::new();
    header.flags(dtn_tcpcl::CAN_TLS).eid("localhost").unwrap();
    stream.write(header.serialize().as_slice()).unwrap();

    let mut buffer: [u8; 100] = [0; 100];
    let mut content_length: usize = 0;
    let mut required: usize = 0;
    stream.set_read_timeout(Some(std::time::Duration::new(5, 0))).unwrap();
    loop {
        let res = stream.read(&mut buffer[content_length..]);
        match res {
            Ok(c) => {
                if c == 0 {
                    eprintln!("No data received");
                    break
                }
                content_length += c;
                if content_length < required {continue}
                let res = dtn_tcpcl::ContactHeader::deserialize(&buffer[..content_length]);
                match res {
                    IResult::Done(i, header) => {
                        println!("{:?}", header);
                        content_length = 0;
                    }
                    IResult::Incomplete(n) => {
                        required = match n {
                            nom::Needed::Unknown => 0,
                            nom::Needed::Size(n) => content_length + n,
                        };
                        continue
                    }
                    IResult::Error(e) => {
                        eprintln!("ERROR PARSING: {}", e);
                        break
                    }
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    continue
                }
                eprintln!("ERROR: {}|{:?}", e, e.kind());
                break;
            }
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both).unwrap();
}