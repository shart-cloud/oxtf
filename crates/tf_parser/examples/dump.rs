//! `cargo run -p tf_parser --example dump -- FILE [--spans] [--norm]`
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let src = std::fs::read_to_string(&args[1]).unwrap();
    let opts = tf_parser::dump::Options {
        spans: args.iter().any(|a| a == "--spans"),
        normalize: args.iter().any(|a| a == "--norm"),
        dedupe_object_keys: false,
    };
    let alloc = tf_allocator::Allocator::new();
    let ret = tf_parser::parse(&alloc, &src);
    println!("{}", tf_parser::dump::dump_file(&ret.file, opts));
    for e in &ret.errors {
        println!("error: {e}");
    }
    println!("comments: {}", ret.comments.len());
}
