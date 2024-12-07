// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Precompiles {
    // Random Bytes
    address public constant RANDOM_BYTES = 0x0100000000000000000000000000000000000001;
    
    // X25519 Derive
    address public constant X25519_DERIVE = 0x0100000000000000000000000000000000000002;
    
    // DeoxysII Seal
    address public constant DEOXYSII_SEAL = 0x0100000000000000000000000000000000000003;
    
    // DeoxysII Open
    address public constant DEOXYSII_OPEN = 0x0100000000000000000000000000000000000004;
    
    // Keypair Generate
    address public constant KEYPAIR_GENERATE = 0x0100000000000000000000000000000000000005;
    
    // Sign
    address public constant SIGN = 0x0100000000000000000000000000000000000006;
    
    // Verify
    address public constant VERIFY = 0x0100000000000000000000000000000000000007;
    
    // Curve25519 Compute Public
    address public constant CURVE25519_COMPUTE_PUBLIC = 0x0100000000000000000000000000000000000008;

    // Oasis-specific, general precompiles
    address public constant SHA512_256 =
        0x0100000000000000000000000000000000000101;
    address public constant SHA512 =
        0x0100000000000000000000000000000000000102;
    address public constant SHA384 =
        0x0100000000000000000000000000000000000104;

    /// Address of the SUBCALL precompile
    address public constant SUBCALL =
        0x0100000000000000000000000000000000000103;
}