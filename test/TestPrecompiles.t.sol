// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import "../src/PrecompileHandler.sol";
import "../src/Precompiles.sol";

contract PrecompileTest is Test, Precompiles {
    PrecompileHandler precompile;
    
    function setUp() public {
        // Deploy precompile 
        precompile = new PrecompileHandler();
    }
    

    function testRandomBytes() public {
        // Modify input data encoding - separate the length and string parameters
        bytes memory inputData = abi.encode(
            uint(32),  // length of random bytes requested
            bytes("test")  // additional entropy
        );

        // Direct low-level call
        (bool success, bytes memory result) = RANDOM_BYTES.call(inputData);
        bytes memory randomBytes = abi.decode(result, (bytes));
        console.log("Hex result: 0x%s", vm.toString(randomBytes));
        assertTrue(success, "Direct call failed");
        assertEq(randomBytes.length, 32, "Incorrect result length");
        
        // Test second call gives different result
        (bool success2, bytes memory result2) = RANDOM_BYTES.call(inputData);
        assertTrue(success2, "Second direct call failed");
        assertNotEq(keccak256(abi.decode(result2, (bytes))), keccak256(result2), "Results should be different");

        (bool success_static, bytes memory result_static) = RANDOM_BYTES.staticcall(inputData);
        bytes memory randomBytes_static = abi.decode(result_static, (bytes));
        console.log("Hex result staticcall: 0x%s", vm.toString(randomBytes_static));
        assertTrue(success_static, "Direct call failed");
        assertEq(randomBytes_static.length, 32, "Incorrect result length");
        assertNotEq(keccak256(result_static), keccak256(result), "Results should be different");
    }

    function testX25519Derive() public {
        // Test vectors from Oasis core 
        bytes32 publicKey = bytes32(hex"3046db3fa70ce605457dc47c48837ebd8bd0a26abfde5994d033e1ced68e2576");
        bytes32 privateKey = bytes32(hex"c07b151fbc1e7a11dff926111188f8d872f62eba0396da97c0a24adb75161750");
        bytes memory expectedOutput = hex"e69ac21066a8c2284e8fdc690e579af4513547b9b31dd144792c1904b45cf586";

        bytes memory inputData = abi.encodePacked(publicKey, privateKey);

        // Direct call
        (bool success, bytes memory result) = X25519_DERIVE.call(inputData);
        assertTrue(success, "Direct call failed");
        assertEq(abi.decode(result, (bytes)), expectedOutput, "Incorrect derived key");

        // Static call
        (bool successStatic, bytes memory resultStatic) = X25519_DERIVE.staticcall(inputData);
        assertTrue(successStatic, "Static call failed");
        assertEq(abi.decode(resultStatic, (bytes)), expectedOutput, "Incorrect derived key from static call");

        // Call through precompile contract
        bytes memory precompileResult = precompile.x25519_derive(publicKey, privateKey);
        assertEq(precompileResult, expectedOutput, "Incorrect derived key from precompile");
    }

    function testCurve25519ComputePublic() public {
        bytes32 privateKey = bytes32(hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        bytes32 expectedPublic = bytes32(hex"8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");

        (bool success, bytes memory result) = CURVE25519_COMPUTE_PUBLIC.call(abi.encodePacked(privateKey));
        assertTrue(success, "Direct call failed");
        assertEq(abi.decode(result, (bytes)), abi.encodePacked(expectedPublic), "Incorrect public key");

        (bool successStatic, bytes memory resultStatic) = CURVE25519_COMPUTE_PUBLIC.staticcall(abi.encodePacked(privateKey));
        assertTrue(successStatic, "Static call failed");
        assertEq(abi.decode(resultStatic, (bytes)), abi.encodePacked(expectedPublic), "Incorrect public key from static call");

        bytes memory precompileResult = precompile.curve25519_compute_public(privateKey);
        assertEq(precompileResult, abi.encodePacked(expectedPublic), "Incorrect public key from precompile");
    }

    function testDeoxysiiSealAndOpen() public {
        bytes32 key = bytes32("this must be the excelentest key");
        bytes32 nonce = bytes32("complete noncence, and too long.");
        bytes memory plaintext = bytes("test message");
        bytes memory ad = bytes("additional data");

        // Add debug logging for inputs
        console.logBytes32(key);
        console.logBytes32(nonce);
        console.logBytes(plaintext);
        console.logBytes(ad);

        // Test seal
        (bool success, bytes memory encrypted_data) = DEOXYSII_SEAL.call(abi.encode(key, nonce, plaintext, ad));
        assertTrue(success, "Seal call failed");
        assertNotEq(abi.decode(encrypted_data, (bytes)), plaintext, "Sealed should differ from plaintext");

        // Add debug logging for encrypted data
        console.logBytes(abi.decode(encrypted_data, (bytes)));

        // Test open
        (bool successOpen, bytes memory opened) = DEOXYSII_OPEN.call(abi.encode(key, nonce, abi.decode(encrypted_data, (bytes)), ad));
        assertTrue(successOpen, "Open call failed");

        // Add debug logging for opened data before decoding
        console.logBytes(opened);
        
        // Log results
        console.log("Encrypted data:", string(abi.decode(encrypted_data, (bytes))));
        console.log("Opened data:", string(opened));
        assertEq(abi.decode(opened, (bytes)), plaintext, "Opened should match original plaintext");

        // Test precompile
        bytes memory precompileSealed = precompile.deoxysii_seal(key, nonce, plaintext, ad);
        bytes memory precompileOpened = precompile.deoxysii_open(key, nonce, precompileSealed, ad);
        assertEq(precompileOpened, plaintext, "Precompile opened should match plaintext");

    }

    function testKeypairGenerateAndSign() public {
        uint256 sigType = 0; // Ed25519_Oasis
        bytes memory seed = bytes("01234567890123456789012345678901");
        bytes memory message = bytes("test message");
        bytes memory context = bytes("test context");

        // Generate keypair
        (bool success, bytes memory result) = KEYPAIR_GENERATE.call(abi.encode(sigType, seed));
        assertTrue(success, "Keypair generation failed");
        
        (bytes memory publicKey, bytes memory privateKey) = abi.decode(result, (bytes, bytes));
        assertTrue(publicKey.length > 0, "Empty public key");
        assertTrue(privateKey.length > 0, "Empty private key");

        // Sign message
        (bool successSign, bytes memory signature) = SIGN.call(
            abi.encode(sigType, privateKey, context, message)
        );
        assertTrue(successSign, "Signing failed");

        // Verify signature
        (bool successVerify, bytes memory verifyResult) = VERIFY.call(
            abi.encode(sigType, publicKey, context, message, signature)
        );
        assertTrue(successVerify, "Verification call failed");
        assertTrue(abi.decode(verifyResult, (bool)), "Signature verification failed");

        // Test precompile
        bytes memory precompileKeys = precompile.keypair_generate(sigType, seed);
        (bytes memory ppubKey, bytes memory pprivKey) = abi.decode(precompileKeys, (bytes, bytes));
        
        bytes memory precompileSig = precompile.sign(sigType, pprivKey, context, message);
        bool precompileVerified = precompile.verify(sigType, ppubKey, context, message, precompileSig);
        assertTrue(precompileVerified, "Precompile signature verification failed");
    }

}