extern crate cc;

fn main() {
    let mut builder = cc::Build::new();
    let build = builder.file("src/trts_pic.S").include("trts_pic");
    build.compile("trts_pic");
}
