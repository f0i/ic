use ic_crypto_sha2::Sha256;
use ic_test_utilities_types::ids::canister_test_id;
use ic_types::{
    crypto::{Signable, SignedBytesWithoutDomainSeparator},
    messages::{Delegation, SignedDelegation},
    time::{Time, UNIX_EPOCH},
};

fn to_hex(data: Vec<u8>) -> String {
    let hex: String = data.iter().map(|byte| format!("{:02x}", byte)).collect();
    return hex;
}

// NOTE: Ideally, this test should be in the types crate where `Delegation` is
// defined, but the test is here to avoid circular dependencies between the
// "types" and "interfaces" crates.
#[test]
fn delegation_signed_bytes() {
    let d = Delegation::new(
        vec![1, 2, 3],
        Time::from_nanos_since_unix_epoch(1234567890123123123),
    );

    let mut expected_signed_bytes = Vec::new();
    expected_signed_bytes.extend_from_slice(b"\x1Aic-request-auth-delegation");

    // Representation-independent hash of the delegation.
    let mut pubkey_hash = Vec::new();
    pubkey_hash.extend_from_slice(&Sha256::hash(b"pubkey"));
    pubkey_hash.extend_from_slice(&Sha256::hash(&[1, 2, 3]));
    println!("asdf pubkey hash {:?}", to_hex(pubkey_hash.clone()));

    let mut expiration_hash = Vec::new();
    expiration_hash.extend_from_slice(&Sha256::hash(b"expiration"));
    expiration_hash.extend_from_slice(&Sha256::hash(&[0]));
    println!("asdf expiration hash {:?}", to_hex(expiration_hash.clone()));

    let mut hashes: Vec<Vec<u8>> = vec![pubkey_hash, expiration_hash];
    hashes.sort();
    println!("asdf sorted: {:?}", hashes);

    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.write(&hash);
    }

    // Concatenate domain with representation-independent hash.
    expected_signed_bytes.extend_from_slice(&hasher.finish());

    println!(
        "signed withot domain seperator: {}",
        to_hex(d.as_signed_bytes_without_domain_separator())
    );
    println!("signed: {}", to_hex(d.as_signed_bytes()));

    assert_eq!(d.as_signed_bytes(), expected_signed_bytes);
    assert_eq!(1, 2);
}

#[test]
fn delegation_with_targets_signed_bytes() {
    let d = Delegation::new_with_targets(vec![1, 2, 3], UNIX_EPOCH, vec![canister_test_id(1)]);

    let mut expected_signed_bytes = Vec::new();
    expected_signed_bytes.extend_from_slice(b"\x1Aic-request-auth-delegation");

    // Representation-independent hash of the delegation.
    let mut pubkey_hash = Vec::new();
    pubkey_hash.extend_from_slice(&Sha256::hash(b"pubkey"));
    pubkey_hash.extend_from_slice(&Sha256::hash(&[1, 2, 3]));

    let mut expiration_hash = Vec::new();
    expiration_hash.extend_from_slice(&Sha256::hash(b"expiration"));
    expiration_hash.extend_from_slice(&Sha256::hash(&[0]));

    let mut targets_hash = Vec::new();
    targets_hash.extend_from_slice(&Sha256::hash(b"targets"));
    targets_hash.extend_from_slice(&Sha256::hash(&Sha256::hash(
        canister_test_id(1).get().as_slice(),
    )));

    let mut hashes: Vec<Vec<u8>> = vec![pubkey_hash, expiration_hash, targets_hash];
    hashes.sort();

    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.write(&hash);
    }

    // Concatenate domain with representation-independent hash.
    expected_signed_bytes.extend_from_slice(&hasher.finish());

    assert_eq!(d.as_signed_bytes(), expected_signed_bytes);
}
