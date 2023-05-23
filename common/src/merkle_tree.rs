use serde::{Serialize, Deserialize};


#[derive(Debug)]
pub enum MerkleTreeError {
    LeavesAreEmpty,
    RootHashMismatch,
    ValueHashMismatch,
    MerkleTreeVerificationFailed,
    BadHexValue,
}

impl std::fmt::Display for MerkleTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleTreeError::LeavesAreEmpty => {
                write!(f, "Empty leaves passed to merkle tree at creation time")
            },
            MerkleTreeError::RootHashMismatch => {
                write!(f, "Root hash doesn't match verification root hash")
            },
            MerkleTreeError::ValueHashMismatch => {
                write!(f, "Value hash doesn't match value hash stored in proof")
            },
            MerkleTreeError::MerkleTreeVerificationFailed => {
                write!(f, "Failed to verify merkle proof, merkle proof has been tampered with")
            },
            MerkleTreeError::BadHexValue => {
                write!(f, "Merkle tree proof has invalid hex values")
            }
        }
    }
}

impl std::error::Error for MerkleTreeError {}

pub struct MerkleTree {
    original_leaf_count: usize,
    tree: Vec<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    proof: Vec<MerkleProofNode>,
    value_hash: String,
    root_hash: String,
}

impl MerkleProof {
    pub fn verify(&self, root_hash: &[u8; 32], value_hash: &[u8; 32]) -> Result<(), MerkleTreeError> {
        if hex::encode(root_hash) != self.root_hash {
            return Err(MerkleTreeError::RootHashMismatch);
        }

        if hex::encode(value_hash) != self.value_hash {
            return Err(MerkleTreeError::ValueHashMismatch);
        }

        let mut current_hash = *value_hash;

        for i in &self.proof {
            match i {
                MerkleProofNode::Left(l) => {
                    // our hash is right
                    let mut hash = hmac_sha256::Hash::new();
                    let bin = hex::decode(l).map_err(|_| {
                        MerkleTreeError::BadHexValue
                    })?;
                    hash.update(&bin);
                    hash.update(current_hash);
                    current_hash = hash.finalize();
                },
                MerkleProofNode::Right(r) => {
                    // our hash is left
                    let mut hash = hmac_sha256::Hash::new();
                    let bin = hex::decode(r).map_err(|_| {
                        MerkleTreeError::BadHexValue
                    })?;
                    hash.update(current_hash);
                    hash.update(&bin);
                    current_hash = hash.finalize();
                },
            }
        }

        if hex::encode(current_hash) != self.root_hash {
            return Err(MerkleTreeError::MerkleTreeVerificationFailed);
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MerkleProofNode {
    Left(String),
    Right(String),
}

impl MerkleTree {
    // Pass in bytes to be hashed
    pub fn new(leaves: &[&[u8]]) -> Result<MerkleTree, MerkleTreeError> {
        let mut hashes = Vec::with_capacity(leaves.len());

        for leave in leaves {
            hashes.push(hmac_sha256::Hash::hash(leave));
        }

        Self::from_existing(&hashes)
    }

    pub fn from_raw(original_leaf_count: usize, hashes: &[[u8; 32]]) -> Result<MerkleTree, MerkleTreeError> {
        if hashes.is_empty() {
            return Err(MerkleTreeError::LeavesAreEmpty);
        }

        let leaves_size = find_next_2nth_number(original_leaf_count);
        let upper_nodes_size = leaves_size - 1;
        let tree_size = upper_nodes_size + leaves_size;

        let mut tree_restored = Vec::with_capacity(tree_size);

        for hash in hashes {
            tree_restored.push(*hash);
        }

        while tree_restored.len() < tree_size {
            tree_restored.push(*tree_restored.last().unwrap());
        }

        Ok(MerkleTree {
            original_leaf_count,
            tree: tree_restored,
        })
    }

    pub fn from_existing(hashes: &[[u8; 32]]) -> Result<MerkleTree, MerkleTreeError> {
        if hashes.is_empty() {
            return Err(MerkleTreeError::LeavesAreEmpty);
        }

        let original_leaf_count = hashes.len();
        let leaves_size = find_next_2nth_number(original_leaf_count);
        let upper_nodes_size = leaves_size - 1;
        let tree_size = upper_nodes_size + leaves_size;
        
        let mut leaves_validated = Vec::with_capacity(tree_size);
        
        // Create unhashed prefix
        for _ in 0..upper_nodes_size {
            // Empty vec is invalid by length but avoids heap allocation and is free to override
            leaves_validated.push([0; 32]);
        }

        for i in hashes {
            leaves_validated.push(*i);
        }

        fill_vec_with_desired_size(&mut leaves_validated, tree_size);

        compute_merkle_hashes(leaves_validated.as_mut_slice());

        Ok(MerkleTree {
            original_leaf_count,
            tree: leaves_validated
        })
    }

    // All merkle tree hashes without duplicates at the end
    pub fn merkle_tree_hashes(&self) -> &[[u8; 32]] {
        &self.tree[0..self.leaf_offset()+self.original_leaf_count]
    }

    // Place where leaf hashes start
    pub fn leaf_offset(&self) -> usize {
        merkle_tree_leaf_start_index(self.tree.len())
    }

    pub fn root_hash(&self) -> &[u8; 32] {
        &self.tree[0]
    }

    pub fn generate_merkle_proof_for_checksum(&self, hash: &[u8; 32]) -> Option<MerkleProof> {
        let tree_size = self.tree.len();

        // Check only leaf nodes
        for idx in merkle_tree_leaf_start_index(self.tree.len())..self.tree.len() {
            if self.tree[idx].as_slice() == hash {
                let mut proof: Vec<MerkleProofNode> = Vec::new();

                let mut target_idx = idx;
                while target_idx > 0 {
                    let neighbor = merkle_tree_get_neighbor(tree_size, target_idx);
                    // assume current index is left and revert if not the case
                    let need_right = target_idx < neighbor;
                    let proof_node = if need_right {
                        MerkleProofNode::Right(hex::encode(self.tree[neighbor]))
                    } else {
                        MerkleProofNode::Left(hex::encode(self.tree[neighbor]))
                    };

                    proof.push(proof_node);

                    target_idx = merkle_tree_parent_index(tree_size, target_idx);
                }

                return Some(MerkleProof { proof, value_hash: hex::encode(hash), root_hash: hex::encode(self.tree[0]) });
            }
        }

        // Value not found
        None
    }

    pub fn generate_merkle_proof_for_value(&self, value: &[u8]) -> Option<MerkleProof> {
        let hash = hmac_sha256::Hash::hash(value);
        self.generate_merkle_proof_for_checksum(&hash)
    }
}

fn compute_merkle_hashes(input: &mut [[u8; 32]]) {
    assert!(is_valid_merkle_tree_size(input.len()));
    // lower order by 2 to keep computing lower and lower tiers
    // Hash the values, starting reverse and going backwards
    let mut tree_order =  input.len();
    while tree_order > 1 {
        assert!(is_valid_merkle_tree_size(tree_order));

        // Reverse iteration is more efficient
        for left_neighbor in (merkle_tree_leaf_start_index(tree_order)..tree_order).step_by(2).rev() {
            // compute parent hashes one order
            let parent_idx = merkle_tree_parent_index(tree_order, left_neighbor);
            let right_neighbor = left_neighbor + 1;

            let mut checksum = hmac_sha256::Hash::new();
            checksum.update(input[left_neighbor]);
            checksum.update(input[right_neighbor]);
            input[parent_idx] = checksum.finalize();
        }

        tree_order /= 2;
    }
}

pub fn copy_merkle_root(from: &[u8], to: &mut [u8; 32]) {
    assert_eq!(from.len(), 32);
    to[..32].copy_from_slice(&from[..32]);
}

fn is_valid_merkle_tree_size(tree_size: usize) -> bool {
    is_number_power_of(tree_size + 1)
}

fn is_number_power_of(number: usize) -> bool {
    (number >= 1) && (number & (number - 1)) == 0
}

fn merkle_tree_parent_index(tree_size: usize, current_index: usize) -> usize {
    assert!(current_index < tree_size);

    let mut idx: i64 = (current_index as i64) / 2;
    if current_index % 2 == 0 {
        idx -= 1;
    }

    assert!(idx >= 0);
    assert!(idx < (tree_size as i64));

    idx as usize
}

fn merkle_tree_get_neighbor(tree_size: usize, current_index: usize) -> usize {
    // Detect underflows early with possibly negative number
    let current_index = current_index as i64;
    let res = if current_index % 2 == 0 {
        current_index - 1
    } else {
        current_index + 1
    };

    assert!(res >= 1);
    assert!(res < tree_size as i64);

    res as usize
}

fn merkle_tree_leaf_start_index(tree_size: usize) -> usize {
    tree_size / 2
}

fn fill_vec_with_desired_size<T: Clone>(input: &mut Vec<T>, desired_size: usize) {
    assert!(!input.is_empty());
    while input.len() < desired_size {
        input.push(input.last().unwrap().clone());
    }
}

// Simple implementation, could possibly be more efficient
// with finding highest order bit and shifting it left if needed
fn find_next_2nth_number(current_length: usize) -> usize {
    assert!(current_length > 0);

    let mut res = 1;
    while res < current_length {
        res *= 2;
    }

    res
}

#[test]
fn test_fill_with_desired_size() {
    let mut test = vec![1, 2, 3];
    fill_vec_with_desired_size(&mut test, 8);
    assert_eq!(test, vec![1, 2, 3, 3, 3, 3, 3, 3]);
}

#[test]
fn test_nth_number() {
    assert_eq!(find_next_2nth_number(3), 4);
    assert_eq!(find_next_2nth_number(2), 2);
    assert_eq!(find_next_2nth_number(7), 8);
    assert_eq!(find_next_2nth_number(8), 8);
    assert_eq!(find_next_2nth_number(1), 1);
}

#[test]
fn test_merkle_tree_parent_index_simple() {
    assert_eq!(merkle_tree_parent_index(7, 6), 2);
    assert_eq!(merkle_tree_parent_index(7, 5), 2);
    assert_eq!(merkle_tree_parent_index(7, 4), 1);
    assert_eq!(merkle_tree_parent_index(7, 3), 1);
    assert_eq!(merkle_tree_parent_index(7, 2), 0);
    assert_eq!(merkle_tree_parent_index(7, 1), 0);
}

#[test]
fn test_merkle_tree_leaf_start_index() {
    assert_eq!(merkle_tree_leaf_start_index(15), 7);
    assert_eq!(merkle_tree_leaf_start_index(7), 3);
    assert_eq!(merkle_tree_leaf_start_index(3), 1);
    assert_eq!(merkle_tree_leaf_start_index(1), 0);
}

#[test]
fn test_merkle_tree_parent_index_simulation() {
    let mut tree_sizes = vec![];
    for i in 1..1024 {
        tree_sizes.push(i * 2 - 1);
    }

    for ts in tree_sizes {
        let mut count_vec = vec![0; ts];
        for i in 1..ts {
            count_vec[merkle_tree_parent_index(ts, i)] += 1;
        }

        // println!("{:?}", count_vec);

        // first half should be all 2s, the second half should be zeroes
        for i in 0..merkle_tree_leaf_start_index(ts) {
            assert_eq!(count_vec[i], 2);
        }

        for i in merkle_tree_leaf_start_index(ts)..ts {
            assert_eq!(count_vec[i], 0);
        }
    }
}

#[test]
fn test_num_power_of_two() {
    assert!(!is_number_power_of(0));
    assert!(is_number_power_of(1));
    assert!(is_number_power_of(2));
    assert!(!is_number_power_of(3));
    assert!(is_number_power_of(4));
    assert!(!is_number_power_of(5));
    assert!(!is_number_power_of(7));
    assert!(is_number_power_of(8));
}

#[test]
fn test_is_valid_merkle_tree_size() {
    assert!(is_valid_merkle_tree_size(1));
    assert!(!is_valid_merkle_tree_size(2));
    assert!(is_valid_merkle_tree_size(3));
    assert!(!is_valid_merkle_tree_size(4));
    assert!(!is_valid_merkle_tree_size(5));
    assert!(is_valid_merkle_tree_size(7));
    assert!(is_valid_merkle_tree_size(15));
    assert!(!is_valid_merkle_tree_size(16));
}

#[test]
fn test_merkle_tree_get_neighbor() {
    assert_eq!(merkle_tree_get_neighbor(7, 1), 2);
    assert_eq!(merkle_tree_get_neighbor(7, 2), 1);
    assert_eq!(merkle_tree_get_neighbor(7, 3), 4);
    assert_eq!(merkle_tree_get_neighbor(7, 4), 3);
    assert_eq!(merkle_tree_get_neighbor(7, 5), 6);
    assert_eq!(merkle_tree_get_neighbor(7, 6), 5);
}

#[test]
#[should_panic]
fn test_merkle_tree_get_neighbor_root_panic() {
    // root has no neighbor
    merkle_tree_get_neighbor(7, 0);
}

#[test]
fn test_compute_merkle_hashes() {
    let leaf_nodes = &[
        "hello",
        "merkle",
        "trees",
        "foo",
    ];

    let mut input: Vec<[u8; 32]> = Vec::with_capacity(leaf_nodes.len() * 2 + 1);
    // fill headers
    for _ in 0..leaf_nodes.len() - 1 {
        input.push([0; 32]);
    }

    for lf_node in leaf_nodes {
        input.push(hmac_sha256::Hash::hash(lf_node.as_bytes()))
    }

    compute_merkle_hashes(input.as_mut_slice());

    let nodes = input.iter().map(|i| {
        hex::encode(&i)
    }).collect::<Vec<_>>();

    // Compute pair of hashes by hand to check like so
    // echo -n f0040964f5aefba61ffed32b36a6bab2b7b35d7b44fa4c32bf76a4d893dc144b4f90dd20248c14f2bd5fa3c8316087592f31d90df0bac4df1ee6b4f1e0cd0b0c | xxd -r -p | sha256sum
    assert_eq!(nodes, [
        "79d1bff5c847a5331b931e454f2dea9da8b5539f2be400ae5dac3904b64f3cba", // H1 + H2
        "f0040964f5aefba61ffed32b36a6bab2b7b35d7b44fa4c32bf76a4d893dc144b", // H3 + H4
        "4f90dd20248c14f2bd5fa3c8316087592f31d90df0bac4df1ee6b4f1e0cd0b0c", // H5 + H6
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", // hello
        "7975edd9e7393c229e744913fe0d0bb86fb4cf46906e2e51152137e20ad15590", // merkle
        "29d807300a961b0cbdb4f22cc5db866a43d20d87b1e17b7f50c91bab25089940", // trees
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", // foo
    ].map(|i| i.to_string()).to_vec());
}


#[test]
fn test_merkle_proof() {
    let leaf_nodes = [
        "hello",
        "merkle",
        "trees",
        "foo",
    ].map(|i| i.as_bytes());

    let mt = MerkleTree::new(&leaf_nodes).unwrap();
    let root_hash = mt.root_hash();

    assert!(mt.generate_merkle_proof_for_value("non existing".as_bytes()).is_none());

    let target_string = "hello";
    let proof = mt.generate_merkle_proof_for_value(target_string.as_bytes()).unwrap();
    assert_eq!(
        proof.proof,
        [
            MerkleProofNode::Right("7975edd9e7393c229e744913fe0d0bb86fb4cf46906e2e51152137e20ad15590".to_string()),
            MerkleProofNode::Right("4f90dd20248c14f2bd5fa3c8316087592f31d90df0bac4df1ee6b4f1e0cd0b0c".to_string()),
        ].as_slice()
    );
    assert!(proof.verify(root_hash, &hmac_sha256::Hash::hash(target_string.as_bytes())).is_ok());

    let target_string = "merkle";
    let proof = mt.generate_merkle_proof_for_value(target_string.as_bytes()).unwrap();
    assert_eq!(
        proof.proof,
        [
            MerkleProofNode::Left("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string()),
            MerkleProofNode::Right("4f90dd20248c14f2bd5fa3c8316087592f31d90df0bac4df1ee6b4f1e0cd0b0c".to_string()),
        ].as_slice()
    );
    assert!(proof.verify(root_hash, &hmac_sha256::Hash::hash(target_string.as_bytes())).is_ok());

    let target_string = "trees";
    let proof = mt.generate_merkle_proof_for_value(target_string.as_bytes()).unwrap();
    assert_eq!(
        proof.proof,
        [
            MerkleProofNode::Right("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae".to_string()),
            MerkleProofNode::Left("f0040964f5aefba61ffed32b36a6bab2b7b35d7b44fa4c32bf76a4d893dc144b".to_string()),
        ].as_slice()
    );
    assert!(proof.verify(root_hash, &hmac_sha256::Hash::hash(target_string.as_bytes())).is_ok());

    let target_string = "foo";
    let proof = mt.generate_merkle_proof_for_value(target_string.as_bytes()).unwrap();
    assert_eq!(
        proof.proof,
        [
            MerkleProofNode::Left("29d807300a961b0cbdb4f22cc5db866a43d20d87b1e17b7f50c91bab25089940".to_string()),
            MerkleProofNode::Left("f0040964f5aefba61ffed32b36a6bab2b7b35d7b44fa4c32bf76a4d893dc144b".to_string()),
        ].as_slice()
    );
    assert!(proof.verify(root_hash, &hmac_sha256::Hash::hash(target_string.as_bytes())).is_ok());
}

#[test]
fn test_merkle_proof_root_hash_mismatch() {
    let leaf_nodes = [
        "hello",
        "merkle",
        "trees",
        "foo",
    ].map(|i| i.as_bytes());

    let mt = MerkleTree::new(&leaf_nodes).unwrap();
    let mut root_hash = mt.root_hash().clone();
    // change root hash
    root_hash[0] ^= 0xff;

    let target_string = "hello";
    let proof = mt.generate_merkle_proof_for_value(target_string.as_bytes()).unwrap();
    match proof.verify(&root_hash, &hmac_sha256::Hash::hash(target_string.as_bytes())).unwrap_err() {
        MerkleTreeError::RootHashMismatch => {},
        _ => { panic!("wrong error") },
    }
}

#[test]
fn test_merkle_proof_value_hash_mismatch() {
    let leaf_nodes = [
        "hello",
        "merkle",
        "trees",
        "foo",
    ].map(|i| i.as_bytes());

    let mt = MerkleTree::new(&leaf_nodes).unwrap();
    let root_hash = mt.root_hash().clone();
    let target_string = "hello";
    // change value hash
    let mut value_hash = hmac_sha256::Hash::hash(target_string.as_bytes());
    value_hash[0] ^= 0xff;

    let proof = mt.generate_merkle_proof_for_value(target_string.as_bytes()).unwrap();
    match proof.verify(&root_hash, &value_hash).unwrap_err() {
        MerkleTreeError::ValueHashMismatch => {},
        _ => { panic!("wrong error") },
    }
}

#[test]
fn test_merkle_proof_tamper_with_proof() {
    let leaf_nodes = [
        "hello",
        "merkle",
        "trees",
        "foo",
    ].map(|i| i.as_bytes());

    let mt = MerkleTree::new(&leaf_nodes).unwrap();
    let root_hash = mt.root_hash().clone();
    let target_string = "hello";
    let value_hash = hmac_sha256::Hash::hash(target_string.as_bytes());

    let mut proof = mt.generate_merkle_proof_for_value(target_string.as_bytes()).unwrap();
    match &mut proof.proof[0] {
        MerkleProofNode::Left(v) => {
            *v = v.replace("0", "1");
        },
        MerkleProofNode::Right(v) => {
            *v = v.replace("0", "1");
        },
    }
    match proof.verify(&root_hash, &value_hash).unwrap_err() {
        MerkleTreeError::MerkleTreeVerificationFailed => {},
        _ => { panic!("wrong error") },
    }
}

#[test]
fn test_merkle_proof_bad_hex() {
    let leaf_nodes = [
        "hello",
        "merkle",
        "trees",
        "foo",
    ].map(|i| i.as_bytes());

    let mt = MerkleTree::new(&leaf_nodes).unwrap();
    let root_hash = mt.root_hash().clone();
    let target_string = "hello";
    let value_hash = hmac_sha256::Hash::hash(target_string.as_bytes());

    let mut proof = mt.generate_merkle_proof_for_value(target_string.as_bytes()).unwrap();
    match &mut proof.proof[0] {
        MerkleProofNode::Left(v) => {
            *v = v.replace("0", "z");
        },
        MerkleProofNode::Right(v) => {
            *v = v.replace("0", "z");
        },
    }
    match proof.verify(&root_hash, &value_hash).unwrap_err() {
        MerkleTreeError::BadHexValue => {},
        _ => { panic!("wrong error") },
    }
}
