mod rsha256;

use rsha256::{sha256, print_hash};

fn main() {
	let exp_string = b"ABC";
	println!("{}", std::str::from_utf8(exp_string).unwrap());
	let hash = sha256(exp_string);
	print_hash(&hash);
	return;
}
