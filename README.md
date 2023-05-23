# Merkle tree storage (mtst)

## Description

This is server and client program where server stores files in s3 compatible storage and has file metadata stored in PostgreSQL database.
Client can upload his immutable directory to the service and retrieve it all when he has merkle root. Only flat file structure is supported.
Client can also verify all his directory contents against the merkle root he saved.

## Features

### Client

- Parallel uploads/downloads (parallelism specified in command line)
- Merkle root verification in the client

### Server

- Prometheus metrics
- Healthcheck

## Testing guide

### (optional) Load reproducible nix environment if available

```
nix-shell shell.nix
```

### Build the executables

```
cargo build --release
```

### Run postgres and minio dependencies with docker compose

```
docker-compose up -d
```

### Check command line flags for all options

```
cargo run --release --bin client -- --help
cargo run --release --bin server -- --help
```

### Once containers are running start running the server

```
cargo run --release --bin server
```

### Open another shell with same nix environment

```
nix-shell shell.nix
```

### Generate ~1.4GB directory for upload test

```
mkdir upload-dir
for I in $(seq 1 100); do head -c 10485760 /dev/urandom | base64 > upload-dir/$I.txt; done
```

### Upload the directory with our client executable to the server

```
cargo run --release --bin client upload -p upload-dir
```

You should receive merkle root like so below
```
Blob uploads done in 3.669s
Directory upload-dir upload successful, time elapsed 3.689s merkle root: 4e42ce7e2bda7aab214f066f481dfd17823ac340197304aed2cf34218bcf26d7
```

### Create other directory to download the files

```
mkdir download-dir
```

### Download the files from the server specifying the previous merkle root
```
cargo run --release --bin client download 4e42ce7e2bda7aab214f066f481dfd17823ac340197304aed2cf34218bcf26d7 -p download-dir
```

On my laptop 1.4G was downloaded in 1.7 seconds
```
Blob downloads done in 1.772s
```

### Compare upload and download folders

```
cd upload-dir && sha256sum * > ../u.txt; cd ..
cd download-dir && sha256sum * > ../d.txt; cd ..
diff -u u.txt d.txt
```

If there are differences, for instance, three files errored out during first download, just repeat the download
```
cargo run --release --bin client download 4e42ce7e2bda7aab214f066f481dfd17823ac340197304aed2cf34218bcf26d7 -p download-dir
```

### Verify all files
```
cargo run --release --bin client verify 4e42ce7e2bda7aab214f066f481dfd17823ac340197304aed2cf34218bcf26d7 -p download-dir
```

### Change file contents and verify again

```
vim download-dir/1.txt # do some changes
cargo run --release --bin client verify 4e42ce7e2bda7aab214f066f481dfd17823ac340197304aed2cf34218bcf26d7 -p download-dir
```
You should see something like this in verify log
```
File 1.txt hashes mismatch, local: 175979127301ae49b6e2cb25b576e13bade61f875c01c6ab984dc0b3ac052be4, remote: 4fcc3e9d424e2695181edeafb2547eb5b0fe1c0cb946a3f4715307a2c9038509
```

### Download files with -o flag to overwrite the changes

```
cargo run --release --bin client download 4e42ce7e2bda7aab214f066f481dfd17823ac340197304aed2cf34218bcf26d7 -p download-dir -o
```

### Verify again

```
cargo run --release --bin client verify 4e42ce7e2bda7aab214f066f481dfd17823ac340197304aed2cf34218bcf26d7 -p download-dir
```

## Low level api guide

### Put file

Hash must match the actual file hash
```
curl --include -XPUT --data-binary @shell.nix http://127.0.0.1:8080/api/v1/blob/7eb6a8a2b4e0fb1f06ea44c3b1018b607a187215b5ab94aa7f21e439e6ed7b3a
curl --include -XPUT --data-binary @docker-compose.yml http://127.0.0.1:8080/api/v1/blob/38718f6949969000f05c96391d43832bd07d12eb8e7343ca19fd4547e97f9722
```

### Retrieve file

```
curl --include http://127.0.0.1:8080/api/v1/blob/7eb6a8a2b4e0fb1f06ea44c3b1018b607a187215b5ab94aa7f21e439e6ed7b3a
```

### Upload dir entries
```
curl --include -XPUT -H 'Content-Type: application/json' --data-binary @entries.json http://127.0.0.1:8080/api/v1/directory
```

### List directory in root merkle tree
```
curl --include http://127.0.0.1:8080/api/v1/directory/59bce0b84da2d467a03d379cd26cc03a61ebc43cd3d807b6a44de5b9919fabf7
```

### Ask for proofs
```
curl --include -XPOST -H 'Content-Type: application/json' --data-binary @proofs.json http://127.0.0.1:8080/api/v1/directory/54e626986205b2f5059694162150e040edf0120e4c1a40d03a788ce69788ebd0/proofs
```
