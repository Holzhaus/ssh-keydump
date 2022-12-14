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
    private::{
        DsaKeypair, EcdsaKeypair, Ed25519Keypair, Ed25519PrivateKey, KeypairData, RsaKeypair,
        SkEcdsaSha2NistP256, SkEd25519,
    },
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
    /// If the key is encrypted, prompt for a passphrase and try to decrypt it.
    #[arg(short, long)]
    decrypt: bool,
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

fn dump_dsa_keypair(keypair: &DsaKeypair) {
    let public_key = &keypair.public;
    println!("Public Key:");
    println!("    p: {:02X?}", public_key.p);
    println!("    q: {:02X?}", public_key.q);
    println!("    g: {:02X?}", public_key.g);
    println!("    y: {:02X?}", public_key.y);
    println!("Private Key:");
    let private_key = &keypair.private;
    println!("    x: {:02X?}", private_key.as_mpint());
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

fn dump_skecdsasha2nistp256_keypair(keypair: &SkEcdsaSha2NistP256) {
    println!("Flags: {:08b}", keypair.flags());
    println!("Key Handle: {:02X?}", keypair.key_handle());
    let public_key = keypair.public();
    println!("Public Key:");
    println!("    Application: {}", public_key.application());
    dump_encoded_point(public_key.ec_point());
}

fn dump_sked25519_keypair(keypair: &SkEd25519) {
    println!("Flags: {:08b}", keypair.flags());
    println!("Key Handle: {:02X?}", keypair.key_handle());
    let public_key = keypair.public();
    println!("Public Key:");
    println!("    Application: {}", public_key.application());
    println!(
        "    data ({} bytes): {:02X?}",
        Ed25519PublicKey::BYTE_SIZE,
        public_key.public_key().0
    );
}

fn dump_private_key(key: PrivateKey, decrypt: bool) -> Result<()> {
    println!("Algorithm: {}", key.algorithm());
    println!("Cipher: {}", key.cipher());
    println!("Comment: {:?}", key.comment());
    println!("Encrypted: {:?}", key.is_encrypted());
    println!("KDF: {:02X?}", key.kdf());
    println!("Fingerprints:");
    println!("    SHA256: {}", key.fingerprint(HashAlg::Sha256));
    println!("    SHA512: {}", key.fingerprint(HashAlg::Sha512));

    // Decrypt key (if applicable and desired).
    let key = if key.is_encrypted() && decrypt {
        let passphrase = rpassword::prompt_password("Passphase: ");
        key.decrypt(passphrase.expect("Failed to read passphrase"))?
    } else {
        key
    };

    match key.key_data() {
        KeypairData::Ecdsa(keypair) => dump_ecdsa_keypair(keypair),
        KeypairData::Ed25519(keypair) => dump_ed25519_keypair(keypair),
        KeypairData::Dsa(keypair) => dump_dsa_keypair(keypair),
        KeypairData::Rsa(keypair) => dump_rsa_keypair(keypair),
        KeypairData::SkEcdsaSha2NistP256(keypair) => dump_skecdsasha2nistp256_keypair(keypair),
        KeypairData::SkEd25519(keypair) => dump_sked25519_keypair(keypair),
        KeypairData::Encrypted(data) => {
            println!("Encrypted Data ({} bytes): {:02X?}", data.len(), &data)
        }
        _ => (),
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let private_key = PrivateKey::read_openssh_file(&args.path)?;
    dump_private_key(private_key, args.decrypt)
}
