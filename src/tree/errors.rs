use crate::ciphersuite::CryptoError;

use super::binary_tree::errors::BinaryTreeError;

implement_error! {
    pub enum TreeError {
        Simple {
            InvalidArguments = "Invalid arguments.",
            InvalidUpdatePath = "The computed update path is invalid.",
            InvalidTree = "The tree is not valid.",
            NotAParentNode = "The node is not a parent node.",
        }
        Complex {
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

implement_error! {
    pub enum ParentHashError {
        Simple {
            EndedWithLeafNode = "The search for a valid child ended with a leaf node.",
            AllChecksFailed = "All checks failed: Neither child has the right parent hash.",
            InputNotParentNode = "The input node is not a parent node.",
            NotAParentNode = "The node is not a parent node.",
            BlankNode = "The parent node was blank.",
        }
        Complex {
            InvalidTree(BinaryTreeError) =
                "Something went wrong while operating on the binary tree. For more information, see `BinaryTreeError`.",
            WrongNodeType(NodeError) = "The given Node was not of the expected type.",
        }
    }
}
