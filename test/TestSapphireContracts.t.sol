// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import "../src/PrecompileHandler.sol";
import "../src/Precompiles.sol";
import "../lib/sapphire-paratime/contracts/contracts/CalldataEncryption.sol";
import "../lib/sapphire-paratime/contracts/contracts/Sapphire.sol";

contract CalldataEncryptionTest is Test {
    PrecompileHandler precompile;
    
    function setUp() public {
        // Deploy precompile 
        precompile = new PrecompileHandler();
    }
    function testEncryptCallData() public {
        // Test with empty data
        bytes memory emptyData = "";
        bytes memory emptyResult = encryptCallData(emptyData);
        assertEq(emptyResult, "", "Empty data should return empty string");

        // Test with actual data
        bytes memory testData = abi.encode("Hello, Sapphire!");
        bytes memory encryptedData = encryptCallData(testData);
        
        // The encrypted data should not be empty
        assertTrue(encryptedData.length > 0, "Encrypted data should not be empty");
        
        // The encrypted data should be different from input
        assertFalse(
            keccak256(encryptedData) == keccak256(testData),
            "Encrypted data should differ from input"
        );

        // Test that multiple encryptions of the same data produce different results
        bytes memory secondEncryption = encryptCallData(testData);
        assertFalse(
            keccak256(encryptedData) == keccak256(secondEncryption),
            "Multiple encryptions should produce different results"
        );
    }

    function testEncryptCallDataWithParams() public {
        bytes memory testData = abi.encode("Hello, Sapphire!");
        
        // Generate key pair
        (
            Sapphire.Curve25519PublicKey myPublic,
            Sapphire.Curve25519SecretKey mySecret
        ) = Sapphire.generateCurve25519KeyPair("");
        
        bytes15 nonce = bytes15(Sapphire.randomBytes(15, ""));
        uint256 epoch = 1;
        bytes32 peerPublicKey = bytes32(uint256(1)); // Mock peer public key

        bytes memory encryptedData = encryptCallData(
            testData,
            myPublic,
            mySecret,
            nonce,
            epoch,
            peerPublicKey
        );

        // Basic validations
        assertTrue(encryptedData.length > 0, "Encrypted data should not be empty");
        assertFalse(
            keccak256(encryptedData) == keccak256(testData),
            "Encrypted data should differ from input"
        );

        // Test with empty data
        bytes memory emptyResult = encryptCallData(
            "",
            myPublic,
            mySecret,
            nonce,
            epoch,
            peerPublicKey
        );
        assertEq(emptyResult, "", "Empty data should return empty string");
    }
}