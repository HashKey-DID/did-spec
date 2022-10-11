## HSK DID Method Specification

This document defines the HSK DID Method that conforms to the [DID Core W3C Spec](https://www.w3.org/TR/did-core), HSK is a DID method that is implemented on PlatOn BlockChain. It uses the DIDDocument contract that stores the information which makes up the DID document for the HSK DID. 

All of the DID Document information is anchored into PlatOn BlockChain. 

## DID Method Name

The HSK DID method is identified by the `hsk` scheme.  A HSK identifier is a simple text string consisting of three parts:

- URL scheme identifier (did)
- Identifier for the DID method (hsk)
- DID method-specific identifier

examples of valid `hsk` DID:

 ```txt
did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c
 ```

A DID that uses this method MUST begin with the following prefix: did:hsk. Per the DID specification, this string MUST be in lowercase. The remainder of the DID, after the prefix, is specified below.



## Method Specific Identifier

The method specific identifier is represented as  the corresponding HEX-encoded PlatOn address on the PlatOn network.

```shell
hsk-did = "did:hsk:"hsk-specific-identifier
hsk-specific-identifier = PlatOn-address
PlatOn-address = 40*HEXDIG
```

## CRUD Operation Definitions

A DID document can only be updated or deactivated by one of its controllers. The `controller` field MAY list the controllers of a document. The default `controller` is the DID subject itself if no controller was provided when invoking `create` function. All of the writing operation MUST be authenticated by the following `authenticate` modifier.

```solidity
modifier authenticate(did,signature);
```

### Create (register)

In order to create a `hsk` DID, Identifier Controller should generate Ecdsa Secp256k1 keys,  At this point, no interaction with the target PlatOn network is required. Invoking `create` function with pramater publicKey, controller, controllerPublicKey, you will get a hsk did, if the controller, controllerPublicKey pramater is null, the default `controller` is the DID subject itself.

```solidity
function create(publicKey,controller,controllerPublicKey);
```

The DID  for  `did:hsk:<PlatOn address>` , e.g. `did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c`

####DID document Example:

```json
{
    "@context":[
        "https://www.w3.org/ns/did/v1"
    ],
    "id":"did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c",
    "controller":["did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c"],
    "verificationMethod":[],
    "authentication":[],
		"assertion":[],
}
```

### Read (Resolve)

HSK DID's associated DID document can be looked up by invoking the `resolve` method of the registry.

To ensure the smart contract invocation result is trustworthy, the client could query a certain number of nodes and then compare the return values or deploy its own node.

The interface method for resolving a PlatOn DID document is defined as follows:

```solidity
function reslove(did);
```

#### DID Document Example

```json
{
    "@context":[
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/secp256k1-2019"
    ],
    "id":"did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c",
    "controller":["did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c"],
    "verificationMethod":[
        {
            "id":"did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c#controller",
            "type":"EcdsaSecp256k1VerificationKey2019",
            "controller":"did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c",
            "publicKeyMultibase":"z26pMHY8dc3gXQ5TyNatpkZJE15qbQsNHeJzMkWrBaWZivgA14bYgCnGwbzPjVHSPoUBA4EQvdoAMwLSmD3LhBmKh"
        },
        {
            "id":"did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c#key-1",
            "type":"EcdsaSecp256k1VerificationKey2019",
            "controller":"did:hsk:a060c1c3807059027ca141efb63f19e12e0cbfvv",
            "publicKeyMultibase":"z6MkpzW2izkFjNwMBwwvKqmELaQcH8t54QL5xmBdJg9Xh1y4"
        }
    ],
    "authentication":[
        "did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c#controller"
    ],
    "assertion":["did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c#controller"],
}
```

### Update (Replace)

To update a HSK DID document, the corresponding DID`Controller` just need to invoke relevant functions.

For instance, the  `DID controller` can invoke the `addAuthentication` method to add a authentication relationship which has the authorization to insert a new verification method into the `authentication` property of the DID Document.

The interface method for updating Document is defined as follows (The operation will only be performed only if the requestor is authorized to perform that operation):

```solidity
function addContext(did,ctx,sig) authenticate(did,sig);
function deleteContext(did,ctx,sig) authenticate(did,sig);
function addAuthentication(did,auth,sig) authenticate(did,sig);
function deleteAuthentication(did,auth,sig) authenticate(did,sig);
function operateVerificationMethod(did,vmId,vmType,controller,pkKey,pkValue) authenticate(did,sig);
function deleteVerificationMethod(did,vmId,sig) authenticate(did,sig);
function addAssertion(did,auth) authenticate(did,sig);
function deleteAssertion(did,auth,sig) authenticate(did,sig);
function addController(did,controller, controllerPublicKey,sig) authenticate(did,sig);
function deleteController(did,controller,sig) authenticate(did,sig);
```

### Delete (Revoke)

To delete (or deactivate) a HSK DID, it suffices to remove all the verification method relationships and verification methods from its associated DID document and set a flag in the registry to indicate the DID is deactivated. In this case, there is no authentication method that can be used to authenticate the holder's identity.

The interface method for deactivating a hsk DID document is defined as follows:

```solidity
function revoke(did,sig) authenticate(did,sig);
```

#### DID Document Example

```json
{
  "id":"did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c",
  "controller":["did:hsk:a060c1c3807059027ca141efb63f19e12e0cbf0c"],
  "deactivated": true
}
```

## Security Considerations

The DID document contract is deployed on the PlatOn BlockChain，all of the write operations MUST be signed by the private key which corresponds to the public key in the DID document. 

Document was protected by blockchain ledger security mechanism, so replay, eavesdropping, denial of service, man-in-the-middle，message insertion，deletion，modification attack are impossible, which can only be modified by one of the controllers who has related private key.
All of the  fields already been defined in document, user can insert incorrect implementation into document.

We provide integrity protection and update authentication for all operations, which makes it impossible to insert, modify or delete message by attacker. Only controllers in document can modify document, which contain controller's public key.

## Privacy Considerations

All data stored in DID document are public, in order to protect users' privacy, we do not support users to store personal privacy data in document. All of the  fields already been defined in document, user can insert privacy data into document.

DID document data published on the blockchain ledger are necessary only for authentication by other parties. So it doesn't matter to be surveillance, the data is public. 

Only the controllers hold the private key in local area and it will not be known to any third party.
