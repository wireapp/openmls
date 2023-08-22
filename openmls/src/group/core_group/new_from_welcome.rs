use openmls_traits::key_store::OpenMlsKeyStore;

use crate::{
    ciphersuite::hash_ref::HashReference,
    group::{core_group::*, errors::WelcomeError},
    prelude::HpkePrivateKey,
    schedule::{
        errors::PskError,
        psk::{store::ResumptionPskStore, ResumptionPsk, ResumptionPskUsage},
    },
    treesync::{
        errors::{DerivePathError, PublicTreeError},
        node::encryption_keys::EncryptionKeyPair,
    },
};

impl CoreGroup {
    // Join a group from a welcome message
    pub async fn new_from_welcome<KeyStore: OpenMlsKeyStore>(
        welcome: Welcome,
        ratchet_tree: Option<RatchetTreeIn>,
        key_package: &KeyPackage,
        key_package_private_key: HpkePrivateKey,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        mut resumption_psk_store: ResumptionPskStore,
    ) -> Result<Self, WelcomeError<KeyStore::Error>> {
        log::debug!("CoreGroup::new_from_welcome_internal");

        // Read the encryption key pair from the key store and delete it there.
        // TODO #1207: Key store access happens as early as possible so it can
        // be pulled up later more easily.
        let leaf_keypair = EncryptionKeyPair::read_from_key_store(
            backend,
            key_package.leaf_node().encryption_key(),
        )
        .await
        .ok_or(WelcomeError::NoMatchingEncryptionKey)?;

        leaf_keypair
            .delete_from_key_store(backend)
            .await
            .map_err(|_| WelcomeError::NoMatchingEncryptionKey)?;

        // Find key_package in welcome secrets
        let egs = if let Some(egs) = Self::find_key_package_from_welcome_secrets(
            key_package.hash_ref(backend.crypto())?,
            welcome.secrets(),
        ) {
            egs
        } else {
            return Err(WelcomeError::JoinerSecretNotFound);
        };

        let ciphersuite = welcome.ciphersuite();
        if ciphersuite != key_package.ciphersuite() {
            return Err(WelcomeError::CiphersuiteMismatch);
        }

        let group_secrets = GroupSecrets::try_from_ciphertext(
            &key_package_private_key,
            egs.encrypted_group_secrets(),
            welcome.encrypted_group_info(),
            ciphersuite,
            backend.crypto(),
        )?;

        // Prepare the PskSecret
        let (has_reinit_branch, psk_secret) = {
            let psks = load_psks(
                backend.key_store(),
                &resumption_psk_store,
                &group_secrets.psks,
            )
            .await?;

            (
                check_welcome_psks(
                    psks.iter()
                        .filter_map(|(psk_id, _)| psk_id.psk().resumption()),
                )?,
                PskSecret::new(backend, ciphersuite, psks).await?,
            )
        };

        // Create key schedule
        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            backend,
            &group_secrets.joiner_secret,
            psk_secret,
        )?;

        // Derive welcome key & nonce from the key schedule
        let (welcome_key, welcome_nonce) = key_schedule
            .welcome(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?
            .derive_welcome_key_nonce(backend)
            .map_err(LibraryError::unexpected_crypto_error)?;

        let verifiable_group_info = VerifiableGroupInfo::try_from_ciphertext(
            &welcome_key,
            &welcome_nonce,
            welcome.encrypted_group_info(),
            &[],
            backend,
        )?;

        // if the welcome has reinit or branch psks the group epoch must be 1
        if has_reinit_branch && verifiable_group_info.context().epoch() != GroupEpoch(1) {
            return Err(WelcomeError::InvalidEpoch);
        }

        // Make sure that we can support the required capabilities in the group info.
        if let Some(required_capabilities) =
            verifiable_group_info.extensions().required_capabilities()
        {
            required_capabilities
                .check_support()
                .map_err(|_| WelcomeError::UnsupportedCapability)?;
            // Also check that our key package actually supports the extensions.
            // Per spec the sender must have checked this. But you never know.
            key_package
                .leaf_node()
                .capabilities()
                .supports_required_capabilities(required_capabilities)?;
        }

        let path_secret_option = group_secrets.path_secret;

        // Build the ratchet tree

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let (ratchet_tree, enable_ratchet_tree_extension) =
            match verifiable_group_info.extensions().ratchet_tree() {
                Some(extension) => (extension.ratchet_tree().clone(), true),
                None => match ratchet_tree {
                    Some(ratchet_tree) => (ratchet_tree, false),
                    None => return Err(WelcomeError::MissingRatchetTree),
                },
            };

        let welcome_sender_index = verifiable_group_info.signer();

        // Since there is currently only the external pub extension, there is no
        // group info extension of interest here.
        let (public_group, _group_info_extensions) = PublicGroup::from_external(
            backend,
            ratchet_tree,
            verifiable_group_info,
            ProposalStore::new(),
        )?;

        KeyPackageIn::from(key_package.clone()).validate(
            backend.crypto(),
            ProtocolVersion::Mls10,
            &public_group,
        )?;

        // Find our own leaf in the tree.
        let own_leaf_index = public_group
            .members()
            .find_map(|m| {
                if m.signature_key == key_package.leaf_node().signature_key().as_slice() {
                    Some(m.index)
                } else {
                    None
                }
            })
            .ok_or(WelcomeError::PublicTreeError(
                PublicTreeError::MalformedTree,
            ))?;

        // If we got a path secret, derive the path (which also checks if the
        // public keys match) and store the derived keys in the key store.
        let group_keypairs = if let Some(path_secret) = path_secret_option {
            let (mut path_keypairs, _commit_secret) = public_group
                .derive_path_secrets(
                    backend,
                    ciphersuite,
                    path_secret,
                    welcome_sender_index,
                    own_leaf_index,
                )
                .map_err(|e| match e {
                    DerivePathError::LibraryError(e) => e.into(),
                    DerivePathError::PublicKeyMismatch => {
                        WelcomeError::PublicTreeError(PublicTreeError::PublicKeyMismatch)
                    }
                })?;
            path_keypairs.push(leaf_keypair);
            path_keypairs
        } else {
            vec![leaf_keypair]
        };

        let (group_epoch_secrets, message_secrets) = {
            let serialized_group_context = public_group
                .group_context()
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;

            // TODO #751: Implement PSK
            key_schedule
                .add_context(backend, &serialized_group_context)
                .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

            let epoch_secrets = key_schedule
                .epoch_secrets(backend)
                .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

            epoch_secrets.split_secrets(
                serialized_group_context,
                public_group.tree_size(),
                own_leaf_index,
            )
        };

        let confirmation_tag = message_secrets
            .confirmation_key()
            .tag(
                backend,
                public_group.group_context().confirmed_transcript_hash(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Verify confirmation tag
        if &confirmation_tag != public_group.confirmation_tag() {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", public_group.confirmation_tag());
            debug_assert!(false, "Confirmation tag mismatch");
            return Err(WelcomeError::ConfirmationTagMismatch);
        }

        let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

        // Extract and store the resumption PSK for the current epoch.
        let resumption_psk = group_epoch_secrets.resumption_psk();
        resumption_psk_store.add(public_group.group_context().epoch(), resumption_psk.clone());

        let group = CoreGroup {
            public_group,
            group_epoch_secrets,
            own_leaf_index,
            use_ratchet_tree_extension: enable_ratchet_tree_extension,
            message_secrets_store,
            resumption_psk_store,
        };
        group
            .store_epoch_keypairs(backend, group_keypairs.into())
            .await
            .map_err(WelcomeError::KeyStoreError)?;

        Ok(group)
    }

    // Helper functions

    pub(crate) fn find_key_package_from_welcome_secrets(
        hash_ref: HashReference,
        welcome_secrets: &[EncryptedGroupSecrets],
    ) -> Option<EncryptedGroupSecrets> {
        for egs in welcome_secrets {
            if &hash_ref == egs.new_member() {
                return Some(egs.clone());
            }
        }
        None
    }
}

/// Checks if there are multiple ocurrences of resumption psks of type Branch or Reinit
/// It will return true if it contains any of those types
fn check_welcome_psks<'i>(
    resumption_psks: impl Iterator<Item = &'i ResumptionPsk>,
) -> Result<bool, PskError> {
    let mut has_branch = false;
    let mut has_reinit = false;
    for resumption in resumption_psks {
        match resumption.usage() {
            ResumptionPskUsage::Branch => {
                if has_branch {
                    return Err(PskError::TooManyBranchReinitResumptionPsks);
                }
                has_branch = true;
            }
            ResumptionPskUsage::Reinit => {
                if has_reinit {
                    return Err(PskError::TooManyBranchReinitResumptionPsks);
                } else {
                    has_reinit = true;
                }
            }
            ResumptionPskUsage::Application => continue,
        }
    }
    Ok(has_reinit || has_branch)
}

#[cfg(test)]
mod tests {
    use crate::{
        group::{GroupEpoch, GroupId},
        schedule::{
            errors::PskError,
            psk::{ResumptionPsk, ResumptionPskUsage},
        },
    };

    use super::check_welcome_psks;

    #[test]
    fn psk_ids_should_be_valid() {
        let group_id = GroupId::from_slice(b"test");
        let epoch = GroupEpoch(1);
        let psks = vec![
            ResumptionPsk::new(ResumptionPskUsage::Reinit, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Branch, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Application, group_id, epoch),
        ];
        assert!(check_welcome_psks(psks.iter()).unwrap());
    }

    #[test]
    fn psk_ids_should_be_valid_application() {
        let group_id = GroupId::from_slice(b"test");
        let epoch = GroupEpoch(1);
        let psks = vec![
            ResumptionPsk::new(ResumptionPskUsage::Application, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Application, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Application, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Application, group_id, epoch),
        ];
        assert!(!check_welcome_psks(psks.iter()).unwrap());
    }

    #[test]
    fn psk_ids_should_be_invalid_reinit() {
        let group_id = GroupId::from_slice(b"test");
        let epoch = GroupEpoch(1);
        let psks = vec![
            ResumptionPsk::new(ResumptionPskUsage::Reinit, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Branch, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Reinit, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Application, group_id, epoch),
        ];
        assert_eq!(
            check_welcome_psks(psks.iter()).unwrap_err(),
            PskError::TooManyBranchReinitResumptionPsks
        );
    }

    #[test]
    fn psk_ids_should_be_invalid_branch() {
        let group_id = GroupId::from_slice(b"test");
        let epoch = GroupEpoch(1);
        let psks = vec![
            ResumptionPsk::new(ResumptionPskUsage::Reinit, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Branch, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Branch, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Application, group_id, epoch),
        ];
        assert_eq!(
            check_welcome_psks(psks.iter()).unwrap_err(),
            PskError::TooManyBranchReinitResumptionPsks
        );
    }

    #[test]
    fn psk_ids_should_be_invalid() {
        let group_id = GroupId::from_slice(b"test");
        let epoch = GroupEpoch(1);
        let psks = vec![
            ResumptionPsk::new(ResumptionPskUsage::Reinit, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Branch, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Reinit, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Branch, group_id.clone(), epoch),
            ResumptionPsk::new(ResumptionPskUsage::Application, group_id, epoch),
        ];
        assert_eq!(
            check_welcome_psks(psks.iter()).unwrap_err(),
            PskError::TooManyBranchReinitResumptionPsks
        );
    }
}
