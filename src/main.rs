// Copyright (c) 2022 Jan Holthuis <jan.holthuis@rub.de>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy
// of the MPL was not distributed with this file, You can obtain one at
// http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

use clap::Parser;
use ssh_key::{HashAlg, PrivateKey, Result};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about)]
#[command(propagate_version = true)]
struct Cli {
    /// File to parse.
    #[arg(value_name = "FILE")]
    path: PathBuf,
}

fn dump_private_key(key: PrivateKey) -> Result<()> {
    println!("Algorithm: {}", key.algorithm());
    println!("Cipher: {}", key.cipher());
    println!("Comment: {:?}", key.comment());
    println!("Encrypted: {:?}", key.is_encrypted());
    println!("KDF: {:02X?}", key.kdf());
    println!("Fingerprints:");
    println!(
        "    SHA256: {:02X?}",
        key.fingerprint(HashAlg::Sha256).as_bytes()
    );
    println!(
        "    SHA512: {:02X?}",
        key.fingerprint(HashAlg::Sha512).as_bytes()
    );

    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let private_key = PrivateKey::read_openssh_file(&args.path)?;
    dump_private_key(private_key)
}
