use std::fs::File;
use std::io::{BufRead, BufReader};

use th::parse;
use th::ThreadInfo;

fn main() {
    let f = File::open("x").expect("error: file 'file.txt' not found.");
    let mut br = BufReader::new(f);
    let mut threads: Vec<ThreadInfo> = vec![];
    parse(&mut br, &mut threads);
}
