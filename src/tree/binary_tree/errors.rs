#[derive(Debug)]
// TODO: Implement this error with the error macro.
pub enum BinaryTreeError {
    IndexOutOfBounds,
    LeafHasNoChildren,
    RootHasNoParent,
}
