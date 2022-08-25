// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
import "./documentDatabase.sol";
import "./strings.sol";

contract Document is DocumentDatabase {
    // lib
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.Bytes32Set;
    using strings for strings.slice;
    /// @dev Emitted when did create successfully 
    event DIDCreateDID(string,string);
    /// @dev Emitted when did update verification method successfully 
    event DIDUpdateVerificationMethod(string,string);
    /// @dev Emitted when did add verification method successfully 
    event DIDAddVerificationMethod(string,string);
    /// @dev Emitted when did delete verification method successfully 
    event DIDDeleteVerificationMethod(string,string);
    /// @dev Emitted when did add context successfully 
    event DIDAddContext(string,string);
    /// @dev Emitted when did delete context successfully 
    event DIDDeleteContext(string,string);
    /// @dev Emitted when did add authentication successfully 
    event DIDAddAuthentication(string,string);
    /// @dev Emitted when did delete authentication successfully 
    event DIDDeleteAuthentication(string,string);
    /// @dev Emitted when did add assertion successfully 
    event DIDAddAssertion(string,string);
    /// @dev Emitted when did delete assertion successfully 
    event DIDDeleteAssertion(string,string);
    /// @dev Emitted when did add controller successfully 
    event DIDAddController(string,string);
    /// @dev Emitted when did delete controller successfully 
    event DIDDeleteController(string,string);
    /// @dev Emitted when did was deleted successfully 
    event DIDDeleteDID(string);

    /// @dev Permits modifications only by the did controller
    /// @dev 1. Get hash value of did with sha256. eg: sha256(did)
    /// @dev 2. Use controller's Private key sign. eg: PrivateKey + Sha256(did) => sig
    /// @param did did identity
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    modifier authenticate(string memory did, bytes memory sig) {
        require(didExist[did], "did not exist");
        bytes32 controller = keccak256(bytes(getDidFromAddress(msg.sender)));
        require(controllerSet[did].contains(controller), "not controller");
        // validate signature
        require(_validate(sha256(bytes(did)), sig, msg.sender));
        _;
    }

    /// @dev Check if did exist
    /// @param did did identity
    modifier exist(string memory did) {
        require(didExist[did], "did not exist");
        _;
    }

    /// @dev Create did 
    /// @param publicKey public key was used to create did
    /// @param controller did controller. eg: did:hsk:b44b38ee93551db49cbaf326c891df4db3dd235b
    function create(
        bytes calldata publicKey,
        string memory controller
    ) public {
        address addr = publicKey2Addr(publicKey);
        bytes memory didBytes = bytes(getDidFromAddress(addr));
        string memory did = string(didBytes);
        require(!didExist[did], "did already exist");
        // add context to did document(JSON-LD)
        _addContext(did, bytes("https://www.w3.org/ns/did/v1"));
        // check controller legal
        if (!checkDidFormat(controller)) {
            // controller not exist
            _addController(did, did);
        } else {
            // controller exist
            _addController(did, controller);
        }
        didExist[did] = true;
        emit DIDCreateDID(did, controllers[keccak256(didBytes)]);
    }

    /// @dev Did add context
    /// @param did did identity
    /// @param ctx doucment context
    function _addContext(string memory did, bytes memory ctx) internal returns (bool, string memory) {
        bytes32 ctxHash = keccak256(ctx);
        if (contextSet[did].contains(ctxHash)) {
            return (false, "context alredy exist");
        }
        contextSet[did].add(ctxHash);
        contexts[ctxHash] = ctx;
        emit DIDAddContext(did, string(ctx));
        return (true, "");
    }

    /// @dev Did add context
    /// @param did did identity
    /// @param ctx doucment context
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function addContext(string memory did, string memory ctx, bytes memory sig) public authenticate(did, sig) {
        bool result;
        string memory resultMsg;
        (result, resultMsg) = _addContext(did, bytes(ctx));
        require(result, resultMsg);
    }

    /// @dev Did delete context
    /// @param did did identity
    /// @param ctx doucment context
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function deleteContext(string memory did, string memory ctx, bytes memory sig) public authenticate(did, sig) {
        bytes32 ctxHash = keccak256(bytes(ctx));
        require(contextSet[did].contains(ctxHash), "ctx not exist");
        contextSet[did].remove(ctxHash);
        emit DIDDeleteContext(did, string(ctx));
    }

    /// @dev Read context
    /// @param did did identity
    function readContext(string memory did) public view exist(did) returns (string memory) {
        bytes memory ctBytes = bytes("[");
        // 
        EnumerableSetUpgradeable.Bytes32Set storage _contextSet = contextSet[did];
        for (uint256 i=0; i<_contextSet.length(); i++) {
           ctBytes = bytes.concat(ctBytes, bytes('\"'), contexts[_contextSet.at(i)] , bytes('\",'));
        }
        ctBytes[ctBytes.length-1] = bytes1("]");
        return string(ctBytes);
    }

    /// @dev Did add controller
    /// @param did did identity
    /// @param controller did controller. eg: did:hsk:b44b38ee93551db49cbaf326c891df4db3dd235b
    function _addController(string memory did, string memory controller) internal {
        bytes32 controllerB32 = keccak256(bytes(controller));
        if (!controllerSet[did].contains(controllerB32)) {
            controllerSet[did].add(controllerB32);
            controllers[controllerB32] = controller;
            emit DIDAddController(did, controller);
        }
    }

    /// @dev Did add controller
    /// @param did did identity
    /// @param controller did controller. eg: did:hsk:b44b38ee93551db49cbaf326c891df4db3dd235b
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function addController(
        string memory did, 
        string memory controller, 
        bytes memory sig
    ) public authenticate(did, sig) {
        require(!controllerSet[did].contains(keccak256(bytes(controller))), "controller already exist");
        _addController(did, controller);
        emit DIDAddController(did, controller);
    }

    /// @dev Did delete controller
    /// @param did did identity
    /// @param controller did controller. eg: did:hsk:b44b38ee93551db49cbaf326c891df4db3dd235b
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function deleteController(string memory did, string memory controller, bytes memory sig) public authenticate(did, sig) {
        bytes32 controllerB32 = keccak256(bytes(controller));
        require(controllerSet[did].contains(controllerB32), "not exist");
        // delete controller
        controllerSet[did].remove(controllerB32);
        controllers[controllerB32] = "";
        // emit event
        emit DIDDeleteController(did, controller);
    }

    /// @dev Read controller
    /// @param did did identity
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

    /// @dev Did add authentication
    /// @param did did identity
    /// @param VMId verification method id
    function _addAuthentication(string memory did, bytes memory VMId) internal returns (bool, string memory) {
        bytes32 VMIdHash = keccak256(bytes(VMId));

        // authenticationSet doesn't contain VMId
        if (authenticationSet[did].contains(VMIdHash)) {
            return (false, "VMId alredy exist in authentication");
        }
        // VerificationMethod id must exist
        if (!verificationMethodIds[did].contains(VMIdHash)) {
            return (false, "VMId not exist in VerificationMethod");
        }
        authenticationSet[did].add(VMIdHash);
        authentications[VMIdHash] = VMId;
        emit DIDAddAuthentication(did, string(VMId));
        return (true, "");
    }

    /// @dev Did add authentication
    /// @param did did identity
    /// @param VMId verification method id
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function addAuthentication(string memory did, string memory VMId, bytes memory sig) public authenticate(did, sig) {
        bool result;
        string memory resultMsg;
        (result, resultMsg) = _addAuthentication(did, bytes(VMId));
        require(result, resultMsg);
    }

    /// @dev Did delete authentication
    /// @param did did identity
    /// @param VMId verification method id
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function deleteAuthentication(string memory did, string memory VMId, bytes memory sig) public authenticate(did, sig) {
       bytes32 VMIdHash = keccak256(bytes(VMId));
       
       require(authenticationSet[did].contains(VMIdHash), "authentication not exist");
       authenticationSet[did].remove(VMIdHash);
       emit DIDDeleteAuthentication(did, string(VMId));
    }

    /// @dev Did read authentication
    /// @param did did identity
    function readAuthentication(string memory did) public view exist(did) returns (string memory) {
        EnumerableSetUpgradeable.Bytes32Set storage _authenticationSet = authenticationSet[did];
        if (_authenticationSet.length() == 0) {
            return '[]';
        }
        // authentication Set is not empty
        bytes memory authBytes = bytes("[");
        for (uint256 i=0; i<_authenticationSet.length(); i++) {
           authBytes = bytes.concat(authBytes, bytes('\"'), authentications[_authenticationSet.at(i)] , bytes('\",'));
        }
        authBytes[authBytes.length-1] = bytes1("]");
        return string(authBytes);
    }

    /// @dev Did add assertion
    /// @param did did identity
    /// @param VMId verification method id
    function _addAssertion(string memory did, bytes memory VMId) internal {
        bytes32 VMIdHash = keccak256(bytes(VMId));
        // VerificationMethod id must exist
        if (assertionSet[did].contains(VMIdHash) && verificationMethodIds[did].contains(VMIdHash)) {
            return;
        }
        assertionSet[did].add(VMIdHash);
        assertions[VMIdHash] = VMId;
        emit DIDAddAssertion(did, string(VMId));
    }

    /// @dev Did add assertion
    /// @param did did identity
    /// @param VMId verification method id
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function addAssertion(string memory did, string memory VMId, bytes memory sig) public authenticate(did, sig) {
        _addAssertion(did, bytes(VMId));
    }

    /// @dev Did delete assertion
    /// @param did did identity
    /// @param VMId verification method id
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function deleteAssertion(string memory did, string memory VMId, bytes memory sig) public authenticate(did, sig) {
       bytes32 VMIdHash = keccak256(bytes(VMId));
       require(assertionSet[did].contains(VMIdHash), "authentication not exist");
       assertionSet[did].remove(VMIdHash);
       emit DIDDeleteAssertion(did, string(VMId));
    }

    /// @dev Did read assertion
    /// @param did did identity
    function readAssertion(string memory did) public view exist(did) returns (string memory) {
        // 
        EnumerableSetUpgradeable.Bytes32Set storage _assertionSet = assertionSet[did];
        if (_assertionSet.length() == 0) {
            return '[]';
        }

        bytes memory assertBytes = bytes("[");
        for (uint256 i=0; i<_assertionSet.length(); i++) {
           assertBytes = bytes.concat(assertBytes, bytes('\"'), assertions[_assertionSet.at(i)] , bytes('\",'));
        }
        assertBytes[assertBytes.length-1] = bytes1("]");
        return string(assertBytes);
    }
    
    /// @dev Did add/update VerificationMethod
    /// @param did did identity
    /// @param VMId verification method id
    /// @param VMType verification method type
    /// @param controller verification method controller
    /// @param pkType public key type
    /// @param pkValue public key value
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function operateVerificationMethod(
        string memory did, 
        string memory VMId, 
        string memory VMType, 
        string memory controller, 
        string memory pkType, 
        string memory pkValue, 
        bytes memory sig
    ) public authenticate(did, sig) {
        _operateVerificationMethod(did, bytes(VMId), bytes(VMType), bytes(controller), bytes(pkType), bytes(pkValue));
    }

    /// @dev Did add/update VerificationMethod
    /// @param did did identity
    /// @param VMId verification method id
    /// @param VMType verification method type
    /// @param controller verification method controller
    /// @param pkType public key type
    /// @param pkValue public key value
    function _operateVerificationMethod(
        string memory did, 
        bytes memory VMId, 
        bytes memory VMType, 
        bytes memory controller, 
        bytes memory pkType, 
        bytes memory pkValue
    ) internal {
        bytes memory b1 = bytes.concat(bytes('{\"id\":\"'), VMId, bytes('\",'));
        bytes memory b2 = bytes.concat(bytes('\"type\":\"'), VMType, bytes('\",'));
        bytes memory b3 = bytes.concat(bytes('\"controller\":\"'), controller, bytes('\",'));
        bytes memory b4 = bytes.concat(bytes('\"'), pkType, bytes('\":\"'), pkValue, bytes('\"}'));
        bytes memory vm = bytes.concat(b1, b2, b3, b4);

        bytes32 vmIdHash = keccak256(VMId);
        if (verificationMethodIds[did].contains(vmIdHash)) {
            emit DIDUpdateVerificationMethod(did, string(vm));
        } else {
            verificationMethodIds[did].add(vmIdHash);
            emit DIDAddVerificationMethod(did, string(vm));
        }
        verificationMethods[did][vmIdHash] = vm;
    }

    /// @dev Did delete VerificationMethod
    /// @param did did identity
    /// @param VMId verification method id
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function deleteVerificationMethod(string memory did,string memory VMId, bytes memory sig) public authenticate(did, sig) {
        bytes32 vmIdHash = keccak256(bytes(VMId));
        require(verificationMethodIds[did].contains(vmIdHash), "verificationMethod id not exist");
        verificationMethodIds[did].remove(vmIdHash);
        verificationMethods[did][vmIdHash] = bytes("");
        emit DIDDeleteVerificationMethod(did, VMId);
    }

    /// @dev Did read VerificationMethod
    /// @param did did identity
    function readVerificationMethod(string memory did) public view exist(did) returns (string memory) {
        EnumerableSetUpgradeable.Bytes32Set storage _verificationMethodIds = verificationMethodIds[did];
        if (_verificationMethodIds.length() == 0) {
            return '[]';
        }
        bytes memory verificationBytes = bytes("[");
        for(uint i=0; i < _verificationMethodIds.length(); i++) {
            bytes memory pk = verificationMethods[did][_verificationMethodIds.at(i)];
            verificationBytes = bytes.concat(verificationBytes, pk, bytes(','));
        }
        verificationBytes[verificationBytes.length-1] = bytes1("]");
        return string(verificationBytes);
    }

    /// @dev Did read document
    /// @param did did identity
    function resolve(string memory did) public exist(did) view returns (string memory) {
        bytes memory document = bytes("{");
        document = bytes.concat(document, bytes('\"@context\":'), bytes(readContext(did)), bytes(','));
        document = bytes.concat(document, bytes('\"id\":'), bytes('\"'),bytes(did), bytes('\",'));
        document = bytes.concat(document, bytes('\"controller\":'), bytes(readController(did)), bytes(','));
        document = bytes.concat(document, bytes('\"verificationMethod\":'), bytes(readVerificationMethod(did)), bytes(','));
        document = bytes.concat(document, bytes('\"authentication\":'), bytes(readAuthentication(did)), bytes(','));
        document = bytes.concat(document, bytes('\"assertionMethod\":'), bytes(readAssertion(did)), bytes(','));
        document[document.length-1] = bytes1("}");
        return string(document);
    }

    /// @dev Did delete document
    /// @param did did identity
    /// @param sig use Ecdsa secp256k1 private key sign sha256(did)
    function revoke(string memory did, bytes memory sig) authenticate(did, sig) public {
        didExist[did] = false;
        emit DIDDeleteDID(did);
    }
    
    /// @dev Check did format
    /// @param did did identity. eg:did:hsk:b9c5714089478a327f09197987f16f9e5d936e8a
    function checkDidFormat(string memory did) public pure returns (bool) {
        strings.slice memory didSlice = strings.toSlice(did);
        if (didSlice.len() != 48 || !didSlice.startsWith(strings.toSlice("did:hsk:"))) {
            return false;
        }
        bytes memory bDid = bytes(did);
        for (uint i=8; i<= 47; i++) {
            uint8 c = uint8(bDid[i]);
            if (!(((c >= 48) && (c <= 57)) || ((c >= 97) && (c <= 122)))) {
                return false;
            }
        }
        
        return true;
    }

    /// @dev Get did By address
    /// @param addr address
    function getDidFromAddress(address addr) public pure returns(string memory) {
        return string.concat("did:hsk:", toString(addr));
    }

    /// @dev Get did By public key
    /// @param publicKey address
    function getDidFromPublicKey(bytes memory publicKey) public pure returns(string memory) {
        address addr = publicKey2Addr(publicKey);
        return string.concat("did:hsk:", toString(addr));
    }

    /// @dev transfer public key(Ecdsa secp256k1) to address
    /// @param publicKey public key
    function publicKey2Addr(bytes memory publicKey) public pure returns(address) {
        address addr = address(uint160(uint256(keccak256(publicKey))));
        return addr;
    }

    /// @dev validate signature
    /// @param message signature text
    /// @param signature signature
    /// @param signer_ signature address
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

    /// @dev transfer address to bytes
    /// @param account address
    function _toBytes(address account) internal pure returns (bytes memory b) {
        assembly {
            let m := mload(0x40)
            account := and(account, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            mstore(
                add(m, 20),
                xor(0x140000000000000000000000000000000000000000, account)
            )
            mstore(0x40, add(m, 52))
            b := m
        }
    }

    /// @dev transfer address to string
    /// @param account address
    function toString(address account) public pure returns(string memory) {
        return toString(abi.encodePacked(account));
    }

    /// @dev transfer bytes to string
    /// @param data bytes data
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