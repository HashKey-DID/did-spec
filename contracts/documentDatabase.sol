// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";

contract DocumentDatabase {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.Bytes32Set;

    /// record did register info
    mapping(string => bool) public didExist;
    /// record did's context info
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) contextSet;
    mapping(bytes32 => bytes) public contexts;
    /// record did's controller info
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) controllerSet;
    mapping(bytes32 => string) public controllers;
    /// record did's verificationMethod info
    mapping(string => mapping(bytes32 => bytes)) public verificationMethods;
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) verificationMethodIds;
    /// record did's authentication info
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) authenticationSet;
    mapping(bytes32 => bytes) public authentications;
    /// record did's assertion info
    mapping(string => EnumerableSetUpgradeable.Bytes32Set) assertionSet;
    mapping(bytes32 => bytes) public assertions;
}