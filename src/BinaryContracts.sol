// SPDX-License-Identifier: MIT
pragma solidity ^0.8.11;

import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";

// Random Bytes Precompile
contract RandomBytesPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        (uint256 numBytes, bytes memory pers) = abi.decode(input, (uint256, bytes));
        require(numBytes <= 1024, "Random: too many bytes requested");
        bytes memory params = abi.encode(numBytes, pers);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/random_bytes";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// X25519 Derive Precompile
contract X25519DerivePrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        (bytes32 publicKey, bytes32 privateKey) = abi.decode(input, (bytes32, bytes32));
        bytes memory params = abi.encodePacked(publicKey, privateKey);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/x25519_derive";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Deoxysii Seal Precompile
contract DeoxysiiSealPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        (bytes32 key, bytes32 nonce, bytes memory plaintext, bytes memory ad) = abi.decode(input, (bytes32, bytes32, bytes, bytes));
        bytes memory params = abi.encode(key, nonce, plaintext, ad);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/deoxysii_seal";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Deoxysii Open Precompile
contract DeoxysiiOpenPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        (bytes32 key, bytes32 nonce, bytes memory ciphertext, bytes memory ad) = abi.decode(input, (bytes32, bytes32, bytes, bytes));
        bytes memory params = abi.encode(key, nonce, ciphertext, ad);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/deoxysii_open";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Curve25519 Compute Public Precompile
contract Curve25519ComputePublicPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        bytes32 privateKey = abi.decode(input, (bytes32));
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/curve25519_compute_public";
        inputs[1] = vm.toString(abi.encodePacked(privateKey));
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Keypair Generate Precompile
contract KeypairGeneratePrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        (uint256 sigType, bytes memory seed) = abi.decode(input, (uint256, bytes));
        bytes memory params = abi.encode(sigType, seed);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/keypair_generate";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Sign Precompile
contract SignPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        (uint256 sigType, bytes memory privateKey, bytes memory context, bytes memory message) = abi.decode(input, (uint256, bytes, bytes, bytes));
        bytes memory params = abi.encode(sigType, privateKey, context, message);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/sign";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Verify Precompile
contract VerifyPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        (uint256 sigType, bytes memory publicKey, bytes memory context, bytes memory message, bytes memory signature) = 
            abi.decode(input, (uint256, bytes, bytes, bytes, bytes));
        bytes memory params = abi.encode(sigType, publicKey, context, message, signature);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/verify";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Gas Used Precompile
contract GasUsedPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata) external returns (bytes memory) {
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/gas_used";
        inputs[1] = vm.toString(bytes(""));
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Pad Gas Precompile
contract PadGasPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        uint128 target = abi.decode(input, (uint128));
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/pad_gas";
        inputs[1] = vm.toString(abi.encode(target));
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Subcall Precompile
contract SubcallPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        (string memory method, bytes memory body) = abi.decode(input, (string, bytes));
        uint256 blockNumber = uint256(vm.getBlockNumber());
        bytes32 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        bytes memory params = abi.encode(blockNumber, method, body, privateKey);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/subcall";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Subcall Precompile
contract SubcallPrecompile2 {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    // Consensus state
    mapping(address => uint256) public consensusBalances;
    mapping(address => mapping(address => uint256)) public delegations; // delegator => validator => shares
    
    // Receipts state
    struct Receipt {
        uint8 kind;      // 1=delegate, 2=undelegate_start, 3=undelegate_done
        uint256 shares;  
        uint256 amount;
        uint256 epoch;
        bytes error;     // optional error
    }
    mapping(address => mapping(uint256 => Receipt)) public receipts;

    fallback(bytes calldata input) external returns (bytes memory) {
        (string memory method, bytes memory body) = abi.decode(input, (string, bytes));
        
        if (method == "consensus.Delegate") {
            // Skip map header (0xa2 or 0xa3)
            uint256 offset = 1;
            uint8 mapPairs = uint8(body[0]) - 0xa0;
            require(mapPairs == 2 || mapPairs == 3, "Invalid map size");
            
            bytes memory to;
            uint128 amount;
            bytes memory token;
            uint64 receiptId;
            bool hasReceipt = false;
            
            for (uint8 i = 0; i < mapPairs; i++) {
                require(body[offset] >= 0x62 && body[offset] <= 0x67, "Invalid key length");
                uint8 keyLen = uint8(body[offset] - 0x60);
                offset += 1;
                bytes memory key = bytes(body[offset:offset + keyLen]);
                offset += keyLen;
                
                if (keccak256(key) == keccak256("to")) {
                    require(body[offset] == 0x55, "Invalid CBOR: expected 21 byte address");
                    offset += 1;
                    to = bytes(body[offset:offset+21]);
                    offset += 21;
                } 
                else if (keccak256(key) == keccak256("amount")) {
                    if (body[offset] == 0x82) { // Array of [amount, token]
                        offset += 1;
                        require(body[offset] == 0x50, "Invalid CBOR: expected 16 byte amount");
                        offset += 1;
                        amount = uint128(bytes16(body[offset:offset+16]));
                        offset += 16;
                        
                        uint8 tokenLen = uint8(body[offset] - 0x40);
                        offset += 1;
                        token = bytes(body[offset:offset+tokenLen]);
                        offset += tokenLen;
                    } else {
                        require(body[offset] == 0x50, "Invalid CBOR: expected 16 byte amount");
                        offset += 1;
                        amount = uint128(bytes16(body[offset:offset+16]));
                        offset += 16;
                    }
                }
                else if (keccak256(key) == keccak256("receipt")) {
                    require(body[offset] == 0x1b, "Invalid CBOR: expected uint64 receipt");
                    offset += 1;
                    receiptId = uint64(bytes8(body[offset:offset+8]));
                    offset += 8;
                    hasReceipt = true;
                    require(receiptId >= 4294967296, "Invalid receipt ID");
                }
            }
            
            // Update state
            address delegator = msg.sender;
            address validator = address(uint160(uint256(bytes32(to))));
            
            // Update delegations and balances
            delegations[delegator][validator] += amount;
            consensusBalances[validator] += amount;
            
            // Store receipt if provided
            if (hasReceipt) {
                receipts[delegator][receiptId] = Receipt({
                    kind: 1, // Delegate
                    shares: 0,  // Will be updated when receipt is taken
                    amount: amount,
                    epoch: uint256(vm.getBlockNumber()),
                    error: ""
                });
            }
        }
        else if (method == "consensus.Undelegate") {
            // Skip map header (0xa2 or 0xa3)
            uint256 offset = 1;
            uint8 mapPairs = uint8(body[0]) - 0xa0;
            require(mapPairs == 2 || mapPairs == 3, "Invalid map size");
            
            bytes memory from;
            uint128 shares;
            uint64 receiptId;
            bool hasReceipt = false;
            
            for (uint8 i = 0; i < mapPairs; i++) {
                require(body[offset] >= 0x62 && body[offset] <= 0x67, "Invalid key length");
                uint8 keyLen = uint8(body[offset] - 0x60);
                offset += 1;
                bytes memory key = bytes(body[offset:offset + keyLen]);
                offset += keyLen;
                
                if (keccak256(key) == keccak256("from")) {
                    require(body[offset] == 0x55, "Invalid CBOR: expected 21 byte address");
                    offset += 1;
                    from = bytes(body[offset:offset+21]);
                    offset += 21;
                }
                else if (keccak256(key) == keccak256("shares")) {
                    require(body[offset] == 0x50, "Invalid CBOR: expected 16 byte amount");
                    offset += 1;
                    shares = uint128(bytes16(body[offset:offset+16]));
                    offset += 16;
                }
                else if (keccak256(key) == keccak256("receipt")) {
                    require(body[offset] == 0x1b, "Invalid CBOR: expected uint64 receipt");
                    offset += 1;
                    receiptId = uint64(bytes8(body[offset:offset+8]));
                    offset += 8;
                    hasReceipt = true;
                    require(receiptId >= 4294967296, "Invalid receipt ID");
                }
            }
            
            // Update state
            address delegator = msg.sender;
            address validator = address(uint160(uint256(bytes32(from))));
            
            // Verify sufficient shares
            require(delegations[delegator][validator] >= shares, "Insufficient shares");
            
            // Update delegations and balances
            delegations[delegator][validator] -= shares;
            consensusBalances[validator] -= shares;
            
            // Store receipt if provided
            if (hasReceipt) {
                receipts[delegator][receiptId] = Receipt({
                    kind: 2, // UndelegateStart
                    shares: shares,
                    amount: 0, // Will be updated when undelegation completes
                    epoch: uint256(vm.getBlockNumber()),
                    error: ""
                });
            }
        }
        else{
            // Continue with FFI call
            uint256 blockNumber = uint256(vm.getBlockNumber());
            bytes32 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
            
            bytes memory params = abi.encode(blockNumber, method, body, privateKey);
            
            string[] memory inputs = new string[](2);
            inputs[0] = "src/precompiles/target/release/subcall";
            inputs[1] = vm.toString(params);
            
            bytes memory response = vm.ffi(inputs);
            (bytes memory result, bytes memory newState) = abi.decode(response, (bytes, bytes));
            return result;
        }
    }

    receive() external payable { revert("No ether accepted"); }
}

// Core Calldata Public Key Precompile
contract CoreCalldataPublicKeyPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata) external returns (bytes memory) {
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/core_calldata_public_key";
        inputs[1] = vm.toString(abi.encodePacked(hex"f6"));
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// Core Current Epoch Precompile
contract CoreCurrentEpochPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata) external returns (bytes memory) {
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/core_current_epoch";
        inputs[1] = vm.toString(abi.encodePacked(hex"f6"));
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

// ROFL Is Authorized Origin Precompile
contract RoflIsAuthorizedOriginPrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        bytes21 appId = abi.decode(input, (bytes21));
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/rofl_is_authorized_origin";
        inputs[1] = vm.toString(abi.encodePacked(hex"55", appId));
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

contract DecodePrecompile {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    fallback(bytes calldata input) external returns (bytes memory) {
        (bytes memory data) = abi.decode(input, (bytes));
        bytes32 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        bytes memory params = abi.encode(data, privateKey);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/decode";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    receive() external payable { revert("No ether accepted"); }
}

abstract contract SapphireDecryptor {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));
    bytes32 private privateKey_ = 0x1234567890123456789012345678901234567890123456789012345678901234;


    fallback(bytes calldata encryptedData) external payable returns (bytes memory) {
        // Try to decrypt using rust binary
        string[] memory inputs = new string[](2);
        bytes memory params = abi.encode(encryptedData, privateKey_);
        inputs[0] = "src/precompiles/target/release/decode";
        inputs[1] = vm.toString(params);
        bytes memory decryptedData = vm.ffi(inputs);
        
        // If data was encrypted (different after decryption)
        if (keccak256(encryptedData) != keccak256(decryptedData)) {
            // Forward the decrypted calldata to this contract
            (bool success, bytes memory result) = address(this).call(decryptedData);
            require(success, "Inner call failed");
            return result;
        }
        
        // If data wasn't encrypted, revert since no matching function was found
        revert("No matching function");
    }

    receive() external payable {}
}