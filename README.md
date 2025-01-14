# Sapphire Precompiles

This project implements Sapphire-compatible precompiles for use with forge tests. It includes support for confidential computing capabilities through encryption/decryption handling.

## Overview

The project provides several key precompiles:

### Cryptographic Operations
- `RandomBytesPrecompile`: Generate random bytes
- `X25519DerivePrecompile`: Derive shared secrets using X25519
- `DeoxysiiSealPrecompile`: Encrypt data using Deoxys-II
- `DeoxysiiOpenPrecompile`: Decrypt data using Deoxys-II
- `Curve25519ComputePublicPrecompile`: Compute public keys

### Key Management
- `KeypairGeneratePrecompile`: Generate cryptographic keypairs
- `SignPrecompile`: Sign messages
- `VerifyPrecompile`: Verify signatures

### Consensus Operations
- `SubcallPrecompile`: Enhanced version with CBOR parsing and state management for:
  - Delegations
  - Undelegations
  - Receipt tracking

### Gas Management
- `GasUsedPrecompile`: Track gas usage
- `PadGasPrecompile`: Adjust gas consumption

## Key Features

1. **Sapphire precompiles as contracts**
   - Can run as native precompiles
   - Easy import into forge tests

2. **Decryption Base contract**
   - Enables decryption at contract level
   - Used as a base contract for other contracts that implement encryption

## Installation and usage
1. **Install dependencies**
    - Go to src/precompiles and build rust bindings
    - `cargo +nightly build --release`

2. **Run tests**
    - To run tests with native precompiles, first import and deploy the BinaryHandler contract `import "../src/BinaryHandler.sol"`
    - In your contract, import and inherit from the SapphireDecryptor contract
    `import { SapphireDecryptor } from "./BinaryContracts.sol";`
    - Run forge tests `forge test`

