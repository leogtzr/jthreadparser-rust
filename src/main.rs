use std::fs::File;
use std::io::BufReader;

fn main() {
    let f = File::open("tdump.sample").expect("error: file 'tdump.sample' not found.");
    let mut br = BufReader::new(f);
    let mut threads: Vec<th::ThreadInfo> = vec![];
    th::parse_from(&mut br, &mut threads);
}
