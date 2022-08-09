use crate::tree::*;

use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

/// Test whether a NodeIndex is a leaf or a parent
#[test]
#[wasm_bindgen_test]
fn test_leaf_parent() {
    // Index 1 should be a parent node
    let index = NodeIndex::from(1usize);
    assert!(!index.is_leaf());
    assert!(index.is_parent());

    // Index 2 should be a parent node
    let index = NodeIndex::from(2usize);
    assert!(index.is_leaf());
    assert!(!index.is_parent());
}
