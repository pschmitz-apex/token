use std::{env, process};
use token::{sig_generator, Config};

// Can either create a token or decode a token; Functionality
// is based on argument pattern; Patterns include:
// Token creation args: environment user_type user
// e.g. $ token uat corr pschmitz
// Token decoding args: decode <token>
// e.g. $ token 49t8wrg9h23...
fn main() {
    // Some tests to run before a potentially failed execution
    token::encoder();

    // Collects and sets configuration variables
    let args: Vec<String> = env::args().collect();
    if args.len() == 4 {
        println!("Making a token...");
        let token_vals = Config::build(&args).unwrap_or_else(|err| {
            println!("Error parsing arguments: {err}");
            process::exit(1)
        });
        sig_generator(token_vals);
    } else if args.len() == 2 {
        println!("Decoding a token...")
    }

}
