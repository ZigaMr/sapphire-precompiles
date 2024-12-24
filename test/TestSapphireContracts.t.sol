// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import "../src/Precompiles.sol";
import "../src/TestCalldataEncryption.sol";
import "../lib/sapphire-paratime/contracts/contracts/Subcall.sol";
import "../lib/sapphire-paratime/contracts/contracts/Sapphire.sol";
import "../src/BinaryHandler.sol";
import "../src/Counter.sol";

contract CalldataEncryptionTest is Test {
    TestCalldataEncryption testCalldataEncryption;
    Precompiles precompiles;
    BinaryHandler binaryHandler;
    Counter counter;
    
    function setUp() public {
        // Deploy precompile 
        testCalldataEncryption = new TestCalldataEncryption();
        precompiles = new Precompiles();
        binaryHandler = new BinaryHandler();
        counter = new Counter();
    }

    function testEncryptCallData() public {
        bytes memory in_data = bytes("Hello, Sapphire!");

        Sapphire.Curve25519PublicKey myPublic;
        Sapphire.Curve25519SecretKey mySecret;

        (myPublic, mySecret) = Sapphire.generateCurve25519KeyPair("");

        bytes15 nonce = bytes15(Sapphire.randomBytes(15, ""));

        Subcall.CallDataPublicKey memory cdpk;
        uint256 epoch;

        (epoch, cdpk) = Subcall.coreCallDataPublicKey();
        bytes memory result = testCalldataEncryption.testEncryptCallData(
            in_data,
            myPublic,
            mySecret,
            nonce,
            epoch,
            cdpk.key
        );
        (bool success, bytes memory decrypted) = address(bytes20(keccak256(bytes("0x987654321098765432109876543210")))).call(abi.encode(result));
        assertEq(success, true);
        assertEq(decrypted, in_data);
    }

    function testCounterEncryptCallData() public {
        bytes memory encryptedData = encryptCallData(abi.encodeWithSelector(counter.increment.selector));
        (bool success, bytes memory decryptedData) = address(bytes20(keccak256(bytes("0x987654321098765432109876543210")))).call(abi.encode(encryptedData));
        assertEq(success, true);
        assertEq(decryptedData, abi.encodeWithSelector(counter.increment.selector));

        console.log("Counter number: ", counter.number());
        uint256 initialNumber = counter.number();
        (success, decryptedData) = address(counter).call(encryptedData);
        assertEq(success, true);
        assertEq(counter.number(), initialNumber + 1);
    }
}
