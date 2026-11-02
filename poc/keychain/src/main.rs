use poc_keychain::{delete, read, write};

const HELP: &str = "kc-poc — System Keychain generic-password PoC

Commands:
  write <service> <account> <value>  Add or update an item (all-app read ACL)
  read <service> <account>           Print the item value
  delete <service> <account>         Delete an item

Options:
  No command-specific options

Global options:
  --help                             Show this help

Environment: see README.md.
";

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|arg| arg == "--help") {
        print!("{HELP}");
        return Ok(());
    }
    match args.as_slice() {
        [command, service, account, value] if command == "write" => {
            write(service, account, value)?;
            println!("written: {service} / {account}");
        }
        [command, service, account] if command == "read" => {
            println!("{}", read(service, account)?);
        }
        [command, service, account] if command == "delete" => {
            delete(service, account)?;
            println!("deleted: {service} / {account}");
        }
        _ => return Err("usage: kc-poc [--help] | write <service> <account> <value> | read <service> <account> | delete <service> <account>".into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("kc-poc: {error}");
        std::process::exit(1);
    }
}
