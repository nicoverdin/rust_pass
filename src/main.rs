mod crypto;
mod vault;

use std::io::{self, IsTerminal, Write};
use std::process;
/* use std::{thread, time}; */

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, OsRng},
};
use clap::{Parser, Subcommand};
use colored::*;
use dialoguer::{Input, Password, Select};
use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;
use vault::{PasswordEntry, Vault};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "PassRust",
    version = "1.1",
    about = "Secure Password Manager CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    Add {
        site: String,
        user: String,
        pass: String,
    },
    Get {
        site: String,
    },
    Update {
        site: String,
        new_pass: String,
    },
    Delete {
        site: String,
    },
    List,
    Gen {
        length: usize,
    },
}

fn print_banner() {
    let banner = r#"
    __________                            __________                __   
    \______   \_____    ______ ______     \______   \__ __  _______/  |_ 
     |     ___/\__  \  /  ___//  ___/      |       _/  |  \/  ___/\   __\
     |    |     / __ \_\___ \ \___ \       |    |   \  |  /\___ \  |  |  
     |____|    (____  /____  >____  > /\   |____|_  /____//____  > |__|  
                    \/     \/     \/  \/          \/           \/        
    "#;
    println!("{}", banner.bright_cyan().bold());
    println!(
        "{}",
        " --- Your Secure Rust Password Manager --- "
            .italic()
            .bright_black()
    );
}

fn get_sensitive_input(prompt: &str) -> Zeroizing<String> {
    print!("{}", prompt.bright_yellow().bold());
    io::stdout().flush().unwrap();

    if io::stdin().is_terminal() {
        let pass = rpassword::read_password().unwrap();
        Zeroizing::new(pass)
    } else {
        let mut file = unsafe { File::from_raw_fd(0) };

        let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        let mut byte = [0u8; 1];

        loop {
            match file.read(&mut byte) {
                Ok(0) => break, // Fin del stream (EOF)
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break; // Fin de línea
                    }
                    buffer.push(byte[0]);
                }
                Err(_) => break,
            }
        }

        std::mem::forget(file);

        let s = String::from_utf8(buffer.to_vec()).unwrap();
        Zeroizing::new(s)
    }
}

fn main() {
    let cli = Cli::parse();

    let mut vault = Vault::load();

    let cipher = {
        let master_pass = get_sensitive_input("Master Password: ");

        crypto::get_cipher(&master_pass, &vault.salt)
    };

    /*     println!("DEBUG: Password scrubbed (cleaned) from RAM. Sleeping 10s...");
       println!("       (Attacker scanning memory now... should find nothing)");
       thread::sleep(time::Duration::from_secs(10));
    */
    match cli.command {
        Some(cmd) => execute_command(cmd, &mut vault, &cipher),
        None => {
            print_banner();
            run_interactive(&mut vault, &cipher);
        }
    }
}

fn execute_command(cmd: Commands, vault: &mut Vault, cipher: &Aes256Gcm) {
    match cmd {
        Commands::Add { site, user, pass } => {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ciphertext = cipher
                .encrypt(&nonce, pass.as_bytes())
                .expect("Encryption failed");

            vault.entries.push(PasswordEntry {
                site: site.clone(),
                username: user,
                ciphertext,
                nonce: nonce.to_vec(),
            });

            vault.save().expect("Failed to save vault file");
            println!(
                "[{}] Entry for '{}' saved {}.",
                "SUCCESS".green().bold(),
                site.bright_white(),
                "successfully".green()
            );
        }

        Commands::Get { site } => {
            if let Some(entry) = vault.find_entry(&site) {
                let nonce = Nonce::from_slice(&entry.nonce);
                match cipher.decrypt(nonce, entry.ciphertext.as_ref()) {
                    Ok(decrypted) => {
                        let pass = String::from_utf8(decrypted).unwrap();
                        println!("\n{}", "--- ACCOUNT DETAILS ---".bright_magenta().bold());
                        println!(
                            "{:<12} {}",
                            "Site:".bright_blue(),
                            entry.site.bright_white()
                        );
                        println!("{:<12} {}", "User:".bright_blue(), entry.username);
                        println!(
                            "{:<12} {}",
                            "Password:".bright_blue(),
                            pass.bright_green().bold()
                        );
                    }
                    Err(_) => {
                        println!(
                            "[{}] Invalid Master Password or corrupted data.",
                            "ERROR".red().bold()
                        );
                        process::exit(1);
                    }
                }
            } else {
                println!(
                    "[{}] No entry found for '{}'.",
                    "NOT FOUND".yellow().bold(),
                    site
                );
                process::exit(1);
            }
        }

        Commands::Update { site, new_pass } => {
            if vault.update_entry(&site, &new_pass, cipher) {
                vault.save().expect("Failed to save vault");
                println!(
                    "[{}] Password for '{}' updated {}.",
                    "SUCCESS".green().bold(),
                    site.bright_white(),
                    "successfully".green()
                );
            } else {
                println!(
                    "[{}] No entry found for '{}'.",
                    "NOT FOUND".yellow().bold(),
                    site
                );
            }
        }

        Commands::Delete { site } => {
            if vault.delete_entry(&site) {
                vault.save().expect("Failed to save vault");
                println!(
                    "[{}] Entry for '{}' has been {}.",
                    "SUCCESS".green().bold(),
                    site.bright_white(),
                    "deleted".red()
                );
            } else {
                println!(
                    "[{}] No entry found for '{}'.",
                    "NOT FOUND".yellow().bold(),
                    site
                );
            }
        }

        Commands::List => {
            if vault.entries.is_empty() {
                println!("[{}] The vault is empty.", "INFO".blue());
            } else {
                println!("\n{}", "--- SAVED ACCOUNTS ---".bright_magenta().bold());
                for entry in &vault.entries {
                    println!(" {} {}", ">".bright_cyan(), entry.site.bright_white());
                }
                println!(
                    "\nTotal: {} accounts.",
                    vault.entries.len().to_string().bright_green()
                );
            }
        }

        Commands::Gen { length } => {
            let password = crypto::generate_password(length);
            println!(
                "[{}] Generated Password: {}",
                "GEN".bright_purple().bold(),
                password.bright_green().bold()
            );
        }
    }
}

fn run_interactive(vault: &mut Vault, cipher: &Aes256Gcm) {
    println!("{}", "\nEntering Interactive Mode...".bright_black());

    loop {
        let selections = &[
            "List Accounts",
            "Get Password",
            "Add New Entry",
            "Update Password",
            "Delete Entry",
            "Generate Password",
            "Exit",
        ];

        let selection = Select::new()
            .with_prompt(format!("{}", "\nWhat would you like to do?".bright_cyan()))
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selection {
            0 => execute_command(Commands::List, vault, cipher),
            1 => {
                let site: String = Input::new()
                    .with_prompt("Enter site name")
                    .interact_text()
                    .unwrap();
                execute_command(Commands::Get { site }, vault, cipher);
            }
            2 => {
                let site: String = Input::new().with_prompt("Site").interact_text().unwrap();
                let user: String = Input::new()
                    .with_prompt("Username")
                    .interact_text()
                    .unwrap();
                let pass: String = Password::new().with_prompt("Password").interact().unwrap();
                execute_command(Commands::Add { site, user, pass }, vault, cipher);
            }
            3 => {
                let site: String = Input::new()
                    .with_prompt("Enter site to update")
                    .interact_text()
                    .unwrap();
                let new_pass: String = Password::new()
                    .with_prompt("New Password")
                    .interact()
                    .unwrap();
                execute_command(Commands::Update { site, new_pass }, vault, cipher);
            }
            4 => {
                let site: String = Input::new()
                    .with_prompt("Enter site to delete")
                    .interact_text()
                    .unwrap();
                execute_command(Commands::Delete { site }, vault, cipher);
            }
            5 => {
                let len: usize = Input::new()
                    .with_prompt("Password length")
                    .default(16)
                    .interact_text()
                    .unwrap();
                execute_command(Commands::Gen { length: len }, vault, cipher);
            }
            6 => {
                println!("{}", "Goodbye!".bright_yellow());
                break;
            }
            _ => unreachable!(),
        }
    }
}
