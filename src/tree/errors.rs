use crate::ciphersuite::CryptoError;
use crate::config::ConfigError;

use super::binary_tree::errors::BinaryTreeError;

implement_error! {
    pub enum TreeError {
        Simple {
            InvalidArguments = "Invalid arguments.",
            InvalidUpdatePath = "The computed update path is invalid.",
            InvalidTree = "The tree is not valid.",
        }
        Complex {
            ConfigError(ConfigError) =
                "See [`ConfigError`](`crate::config::ConfigError`) for details.",
            PathSecretDecryptionError(CryptoError) =
                "Error while decrypting `PathSecret`.",
            InvalidTreeOperation(BinaryTreeError) =
                "Error while performing an operation on the public tree.",
        }
    }
}

implement_error! {
    pub enum NodeError {
        Simple {
            InvalidNodeType = "Invalid node type.",
        }
        Complex {}
    }
}
