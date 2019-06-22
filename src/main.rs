use std::env;
use std::process;

use std::fs::File;
use std::io::BufReader;

fn main() {

    let mut args = env::args();
    args.next();

    let file_name = match args.next() {
        Some(arg) => arg,
        None => {
            eprintln!("error: missing thread dump input file.");
            process::exit(1);
        }
    };

    let f = File::open(file_name).unwrap_or_else(|error| {
        eprintln!("not enough arguments: {}", error);
        process::exit(1);
    });
    let mut br = BufReader::new(f);
    let mut threads: Vec<th::ThreadInfo> = vec![];
    th::parse_from(&mut br, &mut threads);

    for thread in threads {
        println!("{:?}", thread);
    }
    
}
