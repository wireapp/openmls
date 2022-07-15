// "kat_encryption_openmls.json", // DONE
// "kat_key_schedule_openmls.json", // DONE
// "kat_messages.json", // DONE
// "kat_transcripts.json", // DONE
// "kat_tree_kem_openmls.json", // CANNOT DO, issue #624
// "kat_treemath_openmls.json", // DONE

use color_eyre::eyre::Result;
use openmls::{
    prelude::*,
    prelude_test::{kat_treemath::TreeMathTestVector, *},
};
use openmls_rust_crypto::OpenMlsRustCrypto;

fn main() -> Result<()> {
    // TODO: Get the list of needed test vectors (i.e. in ../test_vectors)
    // TODO: Write routines that regenerate those test vectors properly (hex encoding + pretty json serialisation)
    // TODO: Save the files in the appropriate folder
    save_file("test_vectors/kat_treemath_openmls-new.json", kat_treemath())?;
    save_file("test_vectors/kat_messages-new.json", kat_messages())?;
    save_file("test_vectors/kat_transcripts-new.json", kat_transcripts())?;
    // ? https://github.com/openmls/openmls/issues/624
    // save_file("test_vectors/kat_tree_kem_openmls-new.json", kat_tree_kem_openmls())?;
    save_file(
        "test_vectors/kat_key_schedule_openmls-new.json",
        kat_key_schedule_openmls(),
    )?;

    save_file(
        "test_vectors/kat_encryption_openmls-new.json",
        kat_encryption_openmls(),
    )?;

    Ok(())
}

fn save_file(file_path: impl AsRef<std::path::Path>, tests: impl serde::Serialize) -> Result<()> {
    let file_path = file_path.as_ref();
    std::fs::write(file_path, serde_json::to_string_pretty(&tests)?)?;

    Ok(())
}

fn kat_treemath() -> Vec<TreeMathTestVector> {
    let mut tests = Vec::new();

    for n_leaves in 1..99 {
        let test_vector = kat_treemath::generate_test_vector(n_leaves);
        tests.push(test_vector);
    }

    tests
}

fn kat_messages() -> Vec<MessagesTestVector> {
    let mut tests = Vec::new();
    const NUM_TESTS: usize = 100;

    for &ciphersuite in OpenMlsRustCrypto::default()
        .crypto()
        .supported_ciphersuites()
        .iter()
    {
        for _ in 0..NUM_TESTS {
            let test = kat_messages::generate_test_vector(ciphersuite);
            tests.push(test);
        }
    }

    tests
}

fn kat_transcripts() -> Vec<TranscriptTestVector> {
    let mut tests = Vec::new();
    const NUM_TESTS: usize = 100;

    for &ciphersuite in OpenMlsRustCrypto::default()
        .crypto()
        .supported_ciphersuites()
        .iter()
    {
        for _ in 0..NUM_TESTS {
            let test = kat_transcripts::generate_test_vector(ciphersuite);
            tests.push(test);
        }
    }

    tests
}

fn kat_key_schedule_openmls() -> Vec<KeyScheduleTestVector> {
    const NUM_EPOCHS: u64 = 200;
    let mut tests = Vec::new();
    for &ciphersuite in OpenMlsRustCrypto::default()
        .crypto()
        .supported_ciphersuites()
        .iter()
    {
        tests.push(kat_key_schedule::generate_test_vector(
            NUM_EPOCHS,
            ciphersuite,
        ));
    }

    tests
}

fn kat_encryption_openmls() -> Vec<EncryptionTestVector> {
    let mut tests = Vec::new();
    const NUM_LEAVES: u32 = 7;
    const NUM_GENERATIONS: u32 = 5;

    for &ciphersuite in OpenMlsRustCrypto::default()
        .crypto()
        .supported_ciphersuites()
        .iter()
    {
        for n_leaves in 1u32..NUM_LEAVES {
            let test = kat_encryption::generate_test_vector(NUM_GENERATIONS, n_leaves, ciphersuite);
            tests.push(test);
        }
    }

    tests
}
