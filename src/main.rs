// [SM3 Digest Programme]
// Author: XiangXin
// E-mail: ictxiangxin@hotmail.com
// File: main.rs

extern crate core;

use std::env;
use std::io::Error;

mod sm3_digest;
mod sm3_utils;

fn binary_to_hex_string(data: [u8; 32], base: u8) -> String {
    let mut hex_string: String = String::new();
    fn byte_to_hex(byte: u8, base: u8) -> char {
        if byte < 10 { (b'0' + byte) as char } else { (base + byte - 10) as char }
    }
    for byte in data {
        hex_string.push(byte_to_hex(byte / 16, base));
        hex_string.push(byte_to_hex(byte % 16, base));
    }
    hex_string
}

fn usage() {
    println!("SM3 Digest Tool");
    println!("Author: XiangXin");
    println!("Usage:");
    println!("    sm3 [-s|-f] [-x|-X] [String|File]");
    println!("    -s Compute String SM3 Digest.");
    println!("    -f Compute File SM3 Digest.");
    println!("    -x Lower Case Hex String.");
    println!("    -X Upper Case Hex String.");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 4 {
        usage();
        std::process::exit(-1);
    }
    let base: u8;
    match arguments[2].as_str() {
        "-x" => {
            base = b'a';
        }
        "-X" => {
            base = b'A';
        }
        _ => {
            usage();
            std::process::exit(-1);
        }
    }
    match arguments[1].as_str() {
        "-s" => {
            let digest_binary: [u8; 32] = sm3_utils::SM3Utils::sm3_data_digest(arguments[3].as_bytes());
            print!("{}", binary_to_hex_string(digest_binary, base));
            std::process::exit(0);
        }
        "-f" => {
            let digest_binary: Result<[u8; 32], Error> = sm3_utils::SM3Utils::sm3_file_digest(&arguments[3]);
            match digest_binary {
                Ok(binary) => {
                    print!("{}", binary_to_hex_string(binary, base));
                    std::process::exit(0);
                },
                Err(error) => {
                    println!("Error: {error:?}");
                    std::process::exit(-1);
                },
            }
        }
        _ => {
            usage();
            std::process::exit(-1);
        },
    }
}
