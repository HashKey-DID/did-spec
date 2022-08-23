// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
import "./base58.sol";

contract DIDDocument {
    // lib
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.Bytes32Set;
    // event
    event DIDCreateDID(string,string);
    event DIDUpdateVerificationMethod(string,string);
    event DIDAddVerificationMethod(string,string);
    event DIDAddContext(string,string);
    event DIDDeleteContext(string,string);
    event DIDAddAuthentication(string,string);
    event DIDDeleteAuthentication(string,string);
    event DIDAddAssertion(string,string);
    event DIDDeleteAssertion(string,string);
    event DIDAddController(string,string);
    event DIDDeleteController(string,string);
    event DIDDeleteDID(string);

    // todo 是否需要公钥 modifier
    modifier authenticate(string memory did, bytes memory sig) {
        require(didExist[did], "did not exist");
        bytes32 controller = keccak256(getDid(msg.sender));
        require(controllerSet[did].contains(controller), "not controller");
        // 
        bytes memory pk = controllerPKs[controller];
        address controllerAddr = publicKey2Addr(pk);
        require(_validate(sha256(bytes(did)), sig, controllerAddr));
        _;
    }

    modifier exist(string memory did) {
        require(didExist[did], "did not exist");
        _;
    }

    // did -> bool
    mapping(string => bool) public didExist;

    // did -> context[]
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) contextSet;
    mapping(bytes32 => bytes) public contexts;
    
    // did -> controller
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) controllerSet;
    mapping(bytes32 => string) public controllers;
    mapping(bytes32 => bytes) public controllerPKs;
    
    // did -> verificationMethods
    mapping(string => mapping(bytes32 => bytes)) public verificationMethods;
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) verificationMethodIds;
    
    // authentication
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) authenticationSet;
    mapping(bytes32 => bytes) public authentications;
    
    // todo assertion
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) assertionSet;
    mapping(bytes32 => bytes) public assertions;

    // 1. only publicKey paramater
    function create(
        bytes calldata publicKey,
        string memory controller,
        bytes calldata controllerPublicKey
    ) public {
        address addr = publicKey2Addr(publicKey);
        bytes memory didBytes = getDid(addr);
        string memory did = string(didBytes);
        require(!didExist[did], "did already exist");

        // bytes memory vmType = bytes("EcdsaSecp256k1VerificationKey2019");
        // bytes memory vmId;
        // bytes memory vmPK;
        addContext(did, bytes("https://www.w3.org/ns/did/v1"));
        // addContext(did, bytes("https://w3id.org/security/suites/secp256k1-2019"));

        //todo 
        if (!checkDidFormat(controller)) {
            // controller not exist
            // vmId = bytes.concat(didBytes, bytes("#controller"));
            // vmPK = bytes.concat(bytes("z"), Base58.encode(publicKey));
            addController(did, did, publicKey);

            // controllers[did] = did;
            // did2ControllerPK[did] = publicKey;
            // operateVerificationMethod(did, vmId, vmType, didBytes, bytes("publicKeyMultibase"), vmPK);
        } else {
            // controller exist
            // vmId = bytes.concat(bytes(controller), bytes("#controller"));
            // vmPK = bytes.concat(bytes("z"), Base58.encode(controllerPublicKey));
            addController(did, controller, controllerPublicKey);
           
            // controllers[did] = controller;
            // did2ControllerPK[did] = controllerPublicKey;
            // operateVerificationMethod(did, vmId, vmType, bytes(controller), bytes("publicKeyMultibase"), vmPK);
        }
        // add authentication
        // addAuthentication(did, vmId);
        
        didExist[did] = true;
        emit DIDCreateDID(did, controllers[keccak256(didBytes)]);
    }

    /// 
    function addController(string memory did, string memory controller, bytes memory controllerPublicKey) public {
        bytes32 controllerB32 = keccak256(bytes(controller));
        if (!controllerSet[did].contains(controllerB32)) {
            controllerSet[did].add(controllerB32);
            controllers[controllerB32] = controller;
            controllerPKs[controllerB32] = controllerPublicKey;
            emit DIDAddController(did, controller);
        }
    }

    function addController(string memory did, string memory controller, bytes memory controllerPublicKey, bytes memory sig) public authenticate(did, sig) {
        require(controllerSet[did].contains(keccak256(bytes(controller))), "already exist");
        addController(did, controller, controllerPublicKey);
        emit DIDAddController(did, controller);
    }

    // 
    function deleteController(string memory did, string memory controller, bytes memory sig) public authenticate(did, sig) {
        bytes32 controllerB32 = keccak256(bytes(controller));
        require(!controllerSet[did].contains(controllerB32), "not exist");
        //
        controllerSet[did].remove(controllerB32);
        controllers[controllerB32] = "";
        controllerPKs[controllerB32] = bytes("");
        //
        emit DIDDeleteController(did, controller);
    }

    // 
    function readController(string memory did) public view exist(did) returns (string memory) {
        bytes memory ctBytes = bytes("[");
        // 
        EnumerableSetUpgradeable.Bytes32Set storage _controllerSet = controllerSet[did];
        for (uint256 i=0; i<_controllerSet.length(); i++) {
           ctBytes = bytes.concat(ctBytes, bytes('\"'), bytes(controllers[_controllerSet.at(i)]) , bytes('\",'));
        }
        ctBytes[ctBytes.length-1] = bytes1("]");
        return string(ctBytes);
    }

    // context
    function addContext(string memory did, bytes memory ctx) internal {
        bytes32 ctxHash = keccak256(ctx);
        if (contextSet[did].contains(ctxHash)){
            return;
        }
        contextSet[did].add(ctxHash);
        contexts[ctxHash] = ctx;
        emit DIDAddContext(did, string(ctx));
    }

    function addContext(string memory did, string memory ctx, bytes memory sig) public authenticate(did, sig) {
        addContext(did, bytes(ctx));
    }

    function deleteContext(string memory did, string memory ctx, bytes memory sig) public authenticate(did, sig) {
        bytes32 ctxHash = keccak256(bytes(ctx));
       
       require(contextSet[did].contains(ctxHash), "ctx not exist");
       contextSet[did].remove(ctxHash);
       emit DIDDeleteContext(did, string(ctx));
    }

    function readContext(string memory did) public view exist(did) returns (string memory) {
        bytes memory ctBytes = bytes("[");
        // 
        EnumerableSetUpgradeable.Bytes32Set storage _contextSet = contextSet[did];
        for (uint256 i=0; i<_contextSet.length(); i++){
           ctBytes = bytes.concat(ctBytes, bytes('\"'), contexts[_contextSet.at(i)] , bytes('\",'));
        }
        ctBytes[ctBytes.length-1] = bytes1("]");
        return string(ctBytes);
    }

    // authentication
    function addAuthentication(string memory did, bytes memory auth) internal {
        bytes32 authHash = keccak256(bytes(auth));

        // VerificationMethod id must exist.
        if (authenticationSet[did].contains(authHash) && verificationMethodIds[did].contains(authHash)){
            return;
        }
        authenticationSet[did].add(authHash);
        authentications[authHash] = auth;
        emit DIDAddAuthentication(did, string(auth));
    }

    function addAuthentication(string memory did, string memory auth, bytes memory sig) public authenticate(did, sig){
        addAuthentication(did, bytes(auth));
    }

    function deleteAuthentication(string memory did, string memory auth, bytes memory sig) public authenticate(did, sig) {
       bytes32 authHash = keccak256(bytes(auth));
       
       require(authenticationSet[did].contains(authHash), "authentication not exist");
       authenticationSet[did].remove(authHash);
       emit DIDDeleteAuthentication(did, string(auth));
    }

    function readAuthentication(string memory did) public view exist(did) returns (string memory) {
        bytes memory authBytes = bytes("[");
        // 
        EnumerableSetUpgradeable.Bytes32Set storage _authenticationSet = authenticationSet[did];
        for (uint256 i=0; i<_authenticationSet.length(); i++){
           authBytes = bytes.concat(authBytes, bytes('\"'), authentications[_authenticationSet.at(i)] , bytes('\",'));
        }
        authBytes[authBytes.length-1] = bytes1("]");
        return string(authBytes);
    }

    // assertion
    function addAssertion(string memory did, bytes memory auth) internal {
        bytes32 authHash = keccak256(bytes(auth));

        // VerificationMethod id must exist.
        if (assertionSet[did].contains(authHash) && verificationMethodIds[did].contains(authHash)) {
            return;
        }
        assertionSet[did].add(authHash);
        assertions[authHash] = auth;
        emit DIDAddAssertion(did, string(auth));
    }

    function addAssertion(string memory did, string memory auth, bytes memory sig) public authenticate(did, sig) {
        addAssertion(did, bytes(auth));
    }

    function deleteAssertion(string memory did, string memory auth, bytes memory sig) public authenticate(did, sig) {
       bytes32 authHash = keccak256(bytes(auth));
       
       require(assertionSet[did].contains(authHash), "authentication not exist");
       assertionSet[did].remove(authHash);
       emit DIDDeleteAssertion(did, string(auth));
    }

    function readAssertion(string memory did) public view exist(did) returns (string memory) {
        bytes memory assertBytes = bytes("[");
        // 
        EnumerableSetUpgradeable.Bytes32Set storage _assertionSet = assertionSet[did];
        for (uint256 i=0; i<_assertionSet.length(); i++){
           assertBytes = bytes.concat(assertBytes, bytes('\"'), assertions[_assertionSet.at(i)] , bytes('\",'));
        }
        assertBytes[assertBytes.length-1] = bytes1("]");
        return string(assertBytes);
    }

    // add/update VerificationMethod
    function operateVerificationMethod(string memory did, bytes memory vmId, bytes memory vmType, bytes memory controller, bytes memory pkKey, bytes memory pkValue) internal {
        bytes memory b1 = bytes.concat(bytes('{\"id\": \"'), vmId, bytes('\",'));
        bytes memory b2 = bytes.concat(bytes('\"type\": \"'), vmType, bytes('\",'));
        bytes memory b3 = bytes.concat(bytes('\"controller\": \"'), controller, bytes('\",'));
        bytes memory b4 = bytes.concat(bytes('\"'), pkKey, bytes('\": \"'), pkValue, bytes('\"}'));
        bytes memory vm = bytes.concat(b1, b2, b3, b4);

        bytes32 vmIdHash = sha256(vmId);
        if (verificationMethodIds[did].contains(vmIdHash)) {
            emit DIDUpdateVerificationMethod(did, string(vm));
        } else {
            verificationMethodIds[did].add(vmIdHash);
            emit DIDAddVerificationMethod(did, string(vm));
        }
        verificationMethods[did][vmIdHash] = vm;
    }
    
    function operateVerificationMethod(string memory did, string memory vmId, string memory vmType, string memory controller, string memory pkKey, string memory pkValue, bytes memory sig) public authenticate(did, sig) {
        operateVerificationMethod(did, bytes(vmId), bytes(vmType), bytes(controller), bytes(pkKey), bytes(pkValue));
    }

    function deleteVerificationMethod(string memory did,string memory vmId, bytes memory sig) public authenticate(did, sig) {
        bytes32 vmIdHash = sha256(bytes(vmId));
        require(verificationMethodIds[did].contains(vmIdHash), "VerificationMethod Id not exist");
        verificationMethodIds[did].remove(vmIdHash);
        verificationMethods[did][vmIdHash] = bytes("");
    }

    function readVerificationMethod(string memory did) public view exist(did) returns (string memory) {
        bytes memory verificationBytes = bytes("[");
        EnumerableSetUpgradeable.Bytes32Set storage vms = verificationMethodIds[did];
        for(uint i=0; i < vms.length(); i++){
            bytes memory pk = verificationMethods[did][vms.at(i)];
            verificationBytes = bytes.concat(verificationBytes, pk, bytes(','));
        }
        verificationBytes[verificationBytes.length-1] = bytes1("]");
        return string(verificationBytes);
    }

    function resolve(string memory did) public exist(did) view returns (string memory){
        bytes memory document = bytes("{");
        document = bytes.concat(document, bytes('\"@context\":'), bytes(readContext(did)), bytes(','));
        document = bytes.concat(document, bytes('\"id\":'), bytes('\"'),bytes(did), bytes('\",'));
        document = bytes.concat(document, bytes('\"controller\":'), bytes('\"'),bytes(readController(did)), bytes('\",'));
        document = bytes.concat(document, bytes('\"verificationMethod\":'), bytes(readVerificationMethod(did)), bytes(','));
        document = bytes.concat(document, bytes('\"authentication\":'), bytes(readAuthentication(did)), bytes(','));
        document[document.length-1] = bytes1("}");
        return string(document);
    }

    function revoke(string memory did, bytes memory sig) authenticate(did, sig) public {
        didExist[did] = false;
        emit DIDDeleteDID(did);
    }

    // todo
    function checkDidFormat(string memory did) public pure returns (bool) {
        // did:hashkey:0xb9c5714089478a327f09197987f16f9e5d936e8a
        if (bytes(did).length != 52) {
            return false;
        }
        return true;
    }

    function getDid(address addr) public pure returns(bytes memory) {
        return bytes(string.concat("did:hsk:", toString(addr)));
    }

    function publicKey2Addr(bytes memory publicKey) public pure returns(address){
        address addr = address(uint160(uint256(keccak256(publicKey))));
        return addr;
    }

    function _validate(bytes32 message, bytes memory signature, address signer_) internal pure returns (bool) {
        require(signer_ != address(0) && signature.length == 65);
        bytes32 r;
        bytes32 s;
        uint8 v = uint8(signature[64]) + 27;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }
        return ecrecover(message, v, r, s) == signer_;
    }

    function _toBytes(address a) internal pure returns (bytes memory b) {
        assembly {
            let m := mload(0x40)
            a := and(a, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            mstore(
                add(m, 20),
                xor(0x140000000000000000000000000000000000000000, a)
            )
            mstore(0x40, add(m, 52))
            b := m
        }
    }

    function toString(address account) public pure returns(string memory) {
        return toString(abi.encodePacked(account));
    }

    function toString(bytes memory data) public pure returns(string memory) {
        bytes memory alphabet = "0123456789abcdef";

        bytes memory str = new bytes(data.length * 2);
        for (uint i = 0; i < data.length; i++) {
            str[i*2] = alphabet[uint(uint8(data[i] >> 4))];
            str[1+i*2] = alphabet[uint(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }
}









