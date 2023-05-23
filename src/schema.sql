
CREATE TABLE IF NOT EXISTS blobs (
    hash_sha256 TEXT PRIMARY KEY,
    size_bytes INT NOT NULL,
    -- we can garbage collect s3 later
    ref_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS directory_merkle_trees (
    root_hash_sha256 TEXT PRIMARY KEY,
    -- total original leafs
    merkle_tree_leaf_size INT NOT NULL,
    -- value where leaf hashes start
    merkle_tree_leaf_offset INT NOT NULL,
    -- last value repeated for computation
    merkle_tree_hashes TEXT[] NOT NULL,
    merkle_tree_values TEXT[] NOT NULL
);
