// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import "./Precompiles.sol";
import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";

contract PrecompileHandler is Precompiles {
    Vm constant vm = Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));
    
    // Function signatures
    bytes4 constant RANDOM_BYTES_SIG = bytes4(keccak256("random_bytes(uint256,bytes)"));
    bytes4 constant X25519_DERIVE_SIG = bytes4(keccak256("x25519_derive(bytes32,bytes32)"));
    bytes4 constant CURVE25519_COMPUTE_PUBLIC_SIG = bytes4(keccak256("curve25519_compute_public(bytes32)"));
    bytes4 constant DEOXYSII_SEAL_SIG = bytes4(keccak256("deoxysii_seal(bytes32,bytes32,bytes,bytes)"));
    bytes4 constant DEOXYSII_OPEN_SIG = bytes4(keccak256("deoxysii_open(bytes32,bytes32,bytes,bytes)"));
    bytes4 constant KEYPAIR_GENERATE_SIG = bytes4(keccak256("keypair_generate(uint256,bytes)"));
    bytes4 constant SIGN_SIG = bytes4(keccak256("sign(uint256,bytes,bytes,bytes)"));
    bytes4 constant VERIFY_SIG = bytes4(keccak256("verify(uint256,bytes,bytes,bytes,bytes)"));
    bytes4 constant GAS_USED_SIG = bytes4(keccak256("gas_used()"));
    bytes4 constant PAD_GAS_SIG = bytes4(keccak256("pad_gas(uint128)"));
    bytes4 constant SUBCALL_SIG = bytes4(keccak256("subcall(string,bytes)"));
    bytes4 constant CORE_CALLDATAPUBLICKEY_SIG = bytes4(keccak256("core_calldata_public_key()"));
    bytes4 constant CORE_CURRENT_EPOCH_SIG = bytes4(keccak256("core_current_epoch()"));
    bytes4 constant ROFL_IS_AUTHORIZED_ORIGIN_SIG = bytes4(keccak256("rofl_is_authorized_origin(bytes21)"));

    constructor() {
        vm.etch(RANDOM_BYTES, proxyTo(RANDOM_BYTES_SIG));
        vm.label(RANDOM_BYTES, "RANDOM_BYTES");
        
        vm.etch(X25519_DERIVE, proxyTo(X25519_DERIVE_SIG));
        vm.label(X25519_DERIVE, "X25519_DERIVE");
        
        vm.etch(CURVE25519_COMPUTE_PUBLIC, proxyTo(CURVE25519_COMPUTE_PUBLIC_SIG));
        vm.label(CURVE25519_COMPUTE_PUBLIC, "CURVE25519_COMPUTE_PUBLIC");
        
        vm.etch(DEOXYSII_SEAL, proxyTo(DEOXYSII_SEAL_SIG));
        vm.label(DEOXYSII_SEAL, "DEOXYSII_SEAL");
        
        vm.etch(DEOXYSII_OPEN, proxyTo(DEOXYSII_OPEN_SIG));
        vm.label(DEOXYSII_OPEN, "DEOXYSII_OPEN");
        
        vm.etch(KEYPAIR_GENERATE, proxyTo(KEYPAIR_GENERATE_SIG));
        vm.label(KEYPAIR_GENERATE, "KEYPAIR_GENERATE");
        
        vm.etch(SIGN, proxyTo(SIGN_SIG));
        vm.label(SIGN, "SIGN");
        
        vm.etch(VERIFY, proxyTo(VERIFY_SIG));
        vm.label(VERIFY, "VERIFY");

        vm.etch(GAS_USED, proxyTo(GAS_USED_SIG));
        vm.label(GAS_USED, "GAS_USED");
        
        vm.etch(PAD_GAS, proxyTo(PAD_GAS_SIG));
        vm.label(PAD_GAS, "PAD_GAS");

        vm.etch(SUBCALL, proxyTo(SUBCALL_SIG));
        vm.label(SUBCALL, "SUBCALL");

        vm.etch(address(bytes20(keccak256(bytes(CORE_CALLDATAPUBLICKEY)))), proxyTo(CORE_CALLDATAPUBLICKEY_SIG));
        vm.label(address(bytes20(keccak256(bytes(CORE_CALLDATAPUBLICKEY)))), "CORE_CALLDATAPUBLICKEY");
        
        vm.etch(address(bytes20(keccak256(bytes(CORE_CURRENT_EPOCH)))), proxyTo(CORE_CURRENT_EPOCH_SIG));
        vm.label(address(bytes20(keccak256(bytes(CORE_CURRENT_EPOCH)))), "CORE_CURRENT_EPOCH");
        
        vm.etch(address(bytes20(keccak256(bytes(ROFL_IS_AUTHORIZED_ORIGIN)))), proxyTo(ROFL_IS_AUTHORIZED_ORIGIN_SIG));
        vm.label(address(bytes20(keccak256(bytes(ROFL_IS_AUTHORIZED_ORIGIN)))), "ROFL_IS_AUTHORIZED_ORIGIN");
    }

    function random_bytes(uint256 numBytes, bytes calldata pers) public returns (bytes memory) {
        require(numBytes <= 1024, "Random: too many bytes requested");
        bytes memory params = abi.encode(numBytes, pers);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/random_bytes";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }

    function x25519_derive(bytes32 publicKey, bytes32 privateKey) public returns (bytes memory) {
        bytes memory params = abi.encodePacked(publicKey, privateKey);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/x25519_derive";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }

    function deoxysii_seal(bytes32 key, bytes32 nonce, bytes calldata plaintext, bytes calldata ad) public returns (bytes memory) {
        bytes memory params = abi.encode(key, nonce, plaintext, ad);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/deoxysii_seal";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }

    function deoxysii_open(bytes32 key, bytes32 nonce, bytes calldata ciphertext, bytes calldata ad) public returns (bytes memory) {
        bytes memory params = abi.encode(key, nonce, ciphertext, ad);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/deoxysii_open";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }

    function curve25519_compute_public(bytes32 privateKey) public returns (bytes memory) {
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/curve25519_compute_public";
        inputs[1] = vm.toString(abi.encodePacked(privateKey));
        return vm.ffi(inputs);
    }

    function keypair_generate(uint256 sigType, bytes calldata seed) public returns (bytes memory, bytes memory) {
        bytes memory params = abi.encode(sigType, seed);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/keypair_generate";
        inputs[1] = vm.toString(params);
        bytes memory result = vm.ffi(inputs);
        return abi.decode(result, (bytes, bytes));

    }

    function sign(uint256 sigType, bytes calldata privateKey, bytes calldata context, bytes calldata message) public returns (bytes memory) {
        bytes memory params = abi.encode(sigType, privateKey, context, message);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/sign";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }

    function verify(uint256 sigType, bytes calldata publicKey, bytes calldata context, bytes calldata message, bytes calldata signature) public returns (bool) {
        bytes memory params = abi.encode(sigType, publicKey, context, message, signature);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/verify";
        inputs[1] = vm.toString(params);
        bytes memory result = vm.ffi(inputs);
        return abi.decode(result, (bool));
    }


    function gas_used() public returns (uint128) {
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/gas_used";
        inputs[1] = vm.toString(bytes(""));
        bytes memory result = vm.ffi(inputs);
        return uint128(abi.decode(result, (uint256)));
    }

    function pad_gas(uint128 target) public {
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/pad_gas";
        inputs[1] = vm.toString(abi.encode(target));
        vm.ffi(inputs);
    }

    function subcall(string calldata method, bytes calldata body) public returns (bytes memory) {
        uint256 blockNumber = uint256(vm.getBlockNumber());
        bytes32 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        bytes memory params = abi.encode(blockNumber, method, body, privateKey);
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/subcall";
        inputs[1] = vm.toString(params);
        return vm.ffi(inputs);
    }
    
    function core_calldata_public_key() public returns (bytes memory) {
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/core_calldata_public_key";
        inputs[1] = vm.toString(abi.encodePacked(hex"f6"));
        return vm.ffi(inputs);
    }

    function core_current_epoch() public returns (bytes memory) {
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/core_current_epoch";
        inputs[1] = vm.toString(abi.encodePacked(hex"f6"));
        return vm.ffi(inputs);  
    }

    function rofl_is_authorized_origin(bytes21 appId) public returns (bytes memory) {
        string[] memory inputs = new string[](2);
        inputs[0] = "src/precompiles/target/release/rofl_is_authorized_origin";
        inputs[1] = vm.toString(abi.encodePacked(hex"55", appId)); 
        return vm.ffi(inputs);
    }

  function proxyTo(bytes4 sig) internal view returns (bytes memory) {
    address prec = address(this);
    bytes memory ptr;

    assembly {
      ptr := mload(0x40)
      mstore(ptr, 0x60)
      let mc := add(ptr, 0x20)
      let addrPrefix := shl(0xf8, 0x73)
      let addr := shl(0x58, prec)
      let sigPrefix := shl(0x50, 0x63)
      let shiftedSig := shl(0x30, shr(0xe0, sig))
      let suffix := 0x600060043601
      mstore(mc, or(addrPrefix, or(addr, or(sigPrefix, or(shiftedSig, suffix)))))
      mc := add(mc, 0x20)
      mstore(mc, 0x8260e01b82523660006004840137600080828434885af13d6000816000823e82)
      mc := add(mc, 0x20)
      mstore(mc, 0x60008114604a578282f35b8282fd000000000000000000000000000000000000)
      mstore(0x40, add(ptr, 0x80))
    }

    return ptr;
  }
}
