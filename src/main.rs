// Copyright (c) 2022 Jan Holthuis <jan.holthuis@rub.de>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy
// of the MPL was not distributed with this file, You can obtain one at
// http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

use clap::Parser;
use sec1::point::{EncodedPoint, ModulusSize};
use ssh_key::{
    private::{EcdsaKeypair, Ed25519Keypair, Ed25519PrivateKey, KeypairData, RsaKeypair},
    public::Ed25519PublicKey,
    HashAlg, PrivateKey, Result,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about)]
#[command(propagate_version = true)]
struct Cli {
    /// File to parse.
    #[arg(value_name = "FILE")]
    path: PathBuf,
}

fn dump_encoded_point<T>(point: &EncodedPoint<T>)
where
    T: ModulusSize,
{
    println!("  Point ({} bytes):", point.len());
    println!("    Coordinates ({:?}):", point.tag());
    if let Some(x) = point.x() {
        println!("        x: {:02X?}", x);
    }
    if let Some(y) = point.y() {
        println!("        y: {:02X?}", y);
    }
}

fn dump_ecdsa_keypair(keypair: &EcdsaKeypair) {
    println!("Curve: {:?}", keypair.curve());
    match keypair {
        EcdsaKeypair::NistP256 { public, private } => {
            println!("Public Key:");
            dump_encoded_point(public);
            let private = private.as_slice();
            println!("Private Key:");
            println!("  Data ({} bytes): {:02X?}", private.len(), private);
        }
        EcdsaKeypair::NistP384 { public, private } => {
            println!("Public Key:");
            dump_encoded_point(public);
            let private = private.as_slice();
            println!("Private Key:");
            println!("  Data ({} bytes): {:02X?}", private.len(), private);
        }
        EcdsaKeypair::NistP521 { public, private } => {
            println!("Public Key:");
            dump_encoded_point(public);
            let private = private.as_slice();
            println!("Private Key:");
            println!("  Data ({} bytes): {:02X?}", private.len(), private);
        }
    }
}

fn dump_ed25519_keypair(keypair: &Ed25519Keypair) {
    let public_key = &keypair.public;
    println!("Public Key:");
    println!(
        "    data ({} bytes): {:02X?}",
        Ed25519PublicKey::BYTE_SIZE,
        public_key.0
    );
    println!("Private Key:");
    let private_key = &keypair.private;
    println!(
        "    data ({} bytes): {:02X?}",
        Ed25519PrivateKey::BYTE_SIZE,
        private_key.to_bytes()
    );
}

fn dump_rsa_keypair(keypair: &RsaKeypair) {
    let public_key = &keypair.public;
    println!("Public Key:");
    println!("    e: {}", public_key.e);
    println!("    n: {}", public_key.n);
    println!("Private Key:");
    let private_key = &keypair.private;
    println!("    d: {}", private_key.d);
    println!("    iqmp: {}", private_key.iqmp);
    println!("    p: {}", private_key.p);
    println!("    q: {}", private_key.q);
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

    match key.key_data() {
        KeypairData::Ecdsa(keypair) => dump_ecdsa_keypair(keypair),
        KeypairData::Ed25519(keypair) => dump_ed25519_keypair(keypair),
        KeypairData::Rsa(keypair) => dump_rsa_keypair(keypair),
        _ => (),
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let private_key = PrivateKey::read_openssh_file(&args.path)?;
    dump_private_key(private_key)
}
