// Copyright (c) 2022 Jan Holthuis <jan.holthuis@rub.de>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy
// of the MPL was not distributed with this file, You can obtain one at
// http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

use clap::Parser;
use ssh_key::{PrivateKey, Result};
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
    println!("{:#?}", key);

    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let private_key = PrivateKey::read_openssh_file(&args.path)?;
    dump_private_key(private_key)
}
