use openmls::{
    prelude::*,
    test_utils::test_framework::{ActionType, CodecUse, MlsGroupTestSetup},
    test_utils::*,
    *,
};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// The following tests correspond to the interop test scenarios detailed here:
// https://github.com/mlswg/mls-implementations/blob/master/test-scenarios.md
// The tests are conducted for every available ciphersuite, but currently only
// using BasicCredentials. We can change the test setup once #134 is fixed.

fn default_mls_group_config() -> MlsGroupConfig {
    MlsGroupConfig::test_default()
}

// # 1:1 join
// A:    Create group
// B->A: KeyPackage
// A->B: Welcome
// ***:  Verify group state
#[apply(ciphersuites)]
#[wasm_bindgen_test]
async fn one_to_one_join(ciphersuite: Ciphersuite) {
    println!("Testing ciphersuite {:?}", ciphersuite);
    let number_of_clients = 2;
    let setup = MlsGroupTestSetup::new(
        default_mls_group_config(),
        number_of_clients,
        CodecUse::StructMessages,
    )
    .await;

    // Create a group with a random creator.
    let group_id = setup
        .create_group(ciphersuite)
        .await
        .expect("Error while trying to create group.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let (_, alice_id) = group
        .members
        .first()
        .expect("An unexpected error occurred.")
        .clone();

    // A vector including bob's id.
    let bob_id = setup
        .random_new_members_for_group(group, 1)
        .expect("An unexpected error occurred.");

    setup
        .add_clients(ActionType::Commit, group, &alice_id, bob_id)
        .await
        .expect("Error adding Bob");

    // Check that group members agree on a group state.
    setup.check_group_states(group).await;
}

// # 3-party join
// A: Create group
// B->A: KeyPackage
// A->B: Welcome
// C->A: KeyPackage
// A->B: Add(C), Commit
// A->C: Welcome
// ***:  Verify group state
#[apply(ciphersuites)]
#[wasm_bindgen_test]
async fn three_party_join(ciphersuite: Ciphersuite) {
    println!("Testing ciphersuite {:?}", ciphersuite);

    let number_of_clients = 3;
    let setup = MlsGroupTestSetup::new(
        default_mls_group_config(),
        number_of_clients,
        CodecUse::StructMessages,
    )
    .await;

    // Create a group with a random creator.
    let group_id = setup
        .create_group(ciphersuite)
        .await
        .expect("Error while trying to create group.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let (_, alice_id) = group
        .members
        .first()
        .expect("An unexpected error occurred.")
        .clone();

    // A vector including Bob's id.
    let bob_id = setup
        .random_new_members_for_group(group, 1)
        .expect("An unexpected error occurred.");

    // Create the add commit and deliver the welcome.
    setup
        .add_clients(ActionType::Commit, group, &alice_id, bob_id)
        .await
        .expect("Error adding Bob");

    // A vector including Charly's id.
    let charly_id = setup
        .random_new_members_for_group(group, 1)
        .expect("An unexpected error occurred.");

    setup
        .add_clients(ActionType::Commit, group, &alice_id, charly_id)
        .await
        .expect("Error adding Charly");

    // Check that group members agree on a group state.
    setup.check_group_states(group).await;
}

// # Multiple joins at once
// A:    Create group
// B->A: KeyPackage
// C->A: KeyPackage
// A->B: Welcome
// A->C: Welcome
// ***:  Verify group state
#[apply(ciphersuites)]
#[wasm_bindgen_test]
async fn multiple_joins(ciphersuite: Ciphersuite) {
    println!("Testing ciphersuite {:?}", ciphersuite);

    let number_of_clients = 3;
    let setup = MlsGroupTestSetup::new(
        default_mls_group_config(),
        number_of_clients,
        CodecUse::StructMessages,
    )
    .await;

    // Create a group with a random creator.
    let group_id = setup
        .create_group(ciphersuite)
        .await
        .expect("Error while trying to create group.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let (_, alice_id) = group
        .members
        .first()
        .expect("An unexpected error occurred.")
        .clone();

    // A vector including Bob's and Charly's id.
    let bob_charly_id = setup
        .random_new_members_for_group(group, 2)
        .expect("An unexpected error occurred.");

    // Create the add commit and deliver the welcome.
    setup
        .add_clients(ActionType::Commit, group, &alice_id, bob_charly_id)
        .await
        .expect("Error adding Bob and Charly");

    // Check that group members agree on a group state.
    setup.check_group_states(group).await;
}

// TODO #192, #286, #289: The external join test should go here.

// # Update
// A:    Create group
// B->A: KeyPackage
// A->B: Welcome
// A->B: Update, Commit
// ***:  Verify group state
#[apply(ciphersuites)]
#[wasm_bindgen_test]
async fn update(ciphersuite: Ciphersuite) {
    println!("Testing ciphersuite {:?}", ciphersuite);

    let number_of_clients = 2;
    let setup = MlsGroupTestSetup::new(
        default_mls_group_config(),
        number_of_clients,
        CodecUse::StructMessages,
    )
    .await;

    // Create a group with two members. Includes the process of adding Bob.
    let group_id = setup
        .create_random_group(2, ciphersuite)
        .await
        .expect("Error while trying to create group.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let (_, alice_id) = group
        .members
        .first()
        .expect("An unexpected error occurred.")
        .clone();

    // Let Alice create an update with a self-generated KeyPackageBundle.
    setup
        .self_update(ActionType::Commit, group, &alice_id, None)
        .await
        .expect("Error self-updating.");

    // Check that group members agree on a group state.
    setup.check_group_states(group).await;
}

// # Remove
// A:    Create group
// B->A: KeyPackage
// C->A: KeyPackage
// A->B: Welcome
// A->C: Welcome
// A->B: Remove(B), Commit
// ***:  Verify group state
#[apply(ciphersuites)]
#[wasm_bindgen_test]
async fn remove(ciphersuite: Ciphersuite) {
    println!("Testing ciphersuite {:?}", ciphersuite);

    let number_of_clients = 2;
    let setup = MlsGroupTestSetup::new(
        default_mls_group_config(),
        number_of_clients,
        CodecUse::StructMessages,
    )
    .await;

    // Create a group with two members. Includes the process of adding Bob.
    let group_id = setup
        .create_random_group(2, ciphersuite)
        .await
        .expect("Error while trying to create group.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let (_, alice_id) = group
        .members
        .first()
        .expect("An unexpected error occurred.")
        .clone();
    let (bob_index, _) = group
        .members
        .last()
        .expect("An unexpected error occurred.")
        .clone();
    let bob_kpr = setup
        .key_package_ref_by_index(bob_index, group)
        .expect("Couldn't get key package reference.");

    // Have alice remove Bob.
    setup
        .remove_clients(ActionType::Commit, group, &alice_id, &[bob_kpr])
        .await
        .expect("Error removing Bob from the group.");

    // Check that group members agree on a group state.
    setup.check_group_states(group).await;
}

// TODO #141, #284: The external PSK, resumption and re-init tests should go
// here.

// # Large Group, Full Lifecycle
// * Create group
// * Group creator adds the first M members
// * Until group size reaches N members, a randomly-chosen group member adds a
//   new member
// * All members update
// * While the group size is >1, a randomly-chosen group member removes a
//   randomly-chosen other group member
#[apply(ciphersuites)]
#[wasm_bindgen_test]
async fn large_group_lifecycle(ciphersuite: Ciphersuite) {
    println!("Testing ciphersuite {:?}", ciphersuite);

    // "Large" is 20 for now.
    let number_of_clients = 20;
    let setup = MlsGroupTestSetup::new(
        default_mls_group_config(),
        number_of_clients,
        CodecUse::StructMessages,
    )
    .await;

    // Create a group with all available clients. The process includes creating
    // a one-person group and then adding new members in bunches of up to 5,
    // each bunch by a random group member.
    let group_id = setup
        .create_random_group(number_of_clients, ciphersuite)
        .await
        .expect("Error while trying to create group.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let mut group_members = group.members.clone();

    // Have each member in turn update. In between each update, messages are
    // delivered to each member.
    for (_, member_id) in &group_members {
        setup
            .self_update(ActionType::Commit, group, member_id, None)
            .await
            .expect("Error while updating group.")
    }

    while group_members.len() > 1 {
        let remover_id = group.random_group_member();
        let mut target_id = group.random_group_member();
        // Get a random member until it's not the one doing the remove operation.
        while remover_id == target_id {
            target_id = group.random_group_member();
        }
        let target_kpr = setup
            .key_package_ref_by_id(&target_id, group)
            .expect("Couldn't get key package reference.");
        setup
            .remove_clients(ActionType::Commit, group, &remover_id, &[target_kpr])
            .await
            .expect("Error while removing group member.");
        group_members = group.members.clone();
        setup.check_group_states(group).await;
    }

    // Check that group members agree on a group state.
    setup.check_group_states(group).await;
}
