//! Errors for BinaryTree operations.

implement_error! {
    pub enum BinaryTreeError {
        Simple {
            IndexOutOfBounds = "Input index is out of bounds.",
            LeafHasNoChildren = "Attempting to access the child of a leaf.",
            RootHasNoParent = "Attempting to access the parent of the root.",
        }
        Complex {}
    }
}
