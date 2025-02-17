use crate::test_utils::*;
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    messages::{
        proposals::{Proposal, ProposalOrRef, RemoveProposal},
        proposals_in::ProposalOrRefIn,
    },
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// This test encodes and decodes the `ProposalOrRef` struct and makes sure the
/// decoded values are the same as the original
#[apply(ciphersuites_and_backends)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn proposals_codec(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Proposal

    let remove_proposal = RemoveProposal {
        removed: LeafNodeIndex::new(72549),
    };
    let proposal = Proposal::Remove(remove_proposal);
    let proposal_or_ref = ProposalOrRef::Proposal(proposal.clone());
    let encoded = proposal_or_ref
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = ProposalOrRefIn::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");

    assert_eq!(proposal_or_ref, decoded.into());

    // Reference

    let reference = ProposalRef::from_raw_proposal(ciphersuite, backend, &proposal)
        .expect("An unexpected error occurred.");
    let proposal_or_ref = ProposalOrRef::Reference(reference);
    let encoded = proposal_or_ref
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = ProposalOrRefIn::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");

    assert_eq!(proposal_or_ref, decoded.into());
}
