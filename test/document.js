const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Document", async() => {
    let accounts;
    let deployer;
    let document;
    //
    before(async () => {
        accounts = await ethers.getSigners();
        deployer = accounts[0];
    })
    //
    beforeEach(async () => {
        const documentContract = await ethers.getContractFactory("Document");
        document = await documentContract.deploy();
        await document.deployed();
        // create
        await expect(document.connect(accounts[1]).create(
            "0xba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0d67351e5f06073092499336ab0839ef8a521afd334e53807205fa2f08eec74f4",
            "''"));
        // add method

    })

    beforeEach(async () => {
        let did = "did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8";
        let VMId = "did:example:123456789abcdefghi#keys-1";
        let VMType = "EcdsaSecp256k1VerificationKey2019";
        let controller = "did:example:123456789abcdefghi";
        let pkType = "publicKeyHex";
        let pkValue = "034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300";
        let sig = "0x71ff360f26de818058db50fdab06936d9a2c2043ec53cc95bb98d767ca2a190b70324314c4ae11a43f7546b0b973cd4940fc858aeb207d42d370312c0ed03f8700"
        await document.connect(accounts[1]).operateVerificationMethod(did, VMId, VMType, controller, pkType, pkValue, sig);
    })
    
    it("Should be able to create did", async () => {
        await expect(document.connect(accounts[1]).create(
            "0xba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0d67351e5f06073092499336ab0839ef8a521afd334e53807205fa2f08eec74f4",
            "''")).revertedWith("did already exist");
    })

    it("Should be able to get did from public key", async () => {
        let expectDid = "did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8";
        let did = await document.connect(accounts[1]).getDidFromPublicKey("0xba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0d67351e5f06073092499336ab0839ef8a521afd334e53807205fa2f08eec74f4");
        expect(did).equal(expectDid);
    })

    it("Should be able to add/read/delete context", async () => {
        // add context
        let did = "did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8";
        let ctx = "https://w3id.org/security/suites/ed25519-2020/v1";
        let sig = "0x71ff360f26de818058db50fdab06936d9a2c2043ec53cc95bb98d767ca2a190b70324314c4ae11a43f7546b0b973cd4940fc858aeb207d42d370312c0ed03f8700"
        await document.connect(accounts[1]).addContext(did, ctx, sig);
        // read context
        let expectedJson = `["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"]`
        let json = await document.connect(accounts[1]).readContext(did);
        expect(json).equal(expectedJson);
        // delete context
        await document.connect(accounts[1]).deleteContext(did, ctx, sig);
        // read context
        expectedJson = `["https://www.w3.org/ns/did/v1"]`
        json = await document.connect(accounts[1]).readContext(did);
        expect(json).equal(expectedJson);
    })
    
    it("Should be able to add/read/delete controller", async () => {
        // add controller
        let did = "did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8";
        let controller = "did:hsk:3c44cdddb6a900fa2b585dd299e03d12fa4293bc";
        let sig = "0x71ff360f26de818058db50fdab06936d9a2c2043ec53cc95bb98d767ca2a190b70324314c4ae11a43f7546b0b973cd4940fc858aeb207d42d370312c0ed03f8700"
        await document.connect(accounts[1]).addController(did, controller, sig);
        // read controller
        let expectedJson = `["did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8","did:hsk:3c44cdddb6a900fa2b585dd299e03d12fa4293bc"]`
        let json = await document.connect(accounts[1]).readController(did);
        expect(json).equal(expectedJson);
        // delete context
        let sig2 = "0x1210dcdfe0fa598eaf414f5b8b4b6ed317f39cf1ef081c904fa31ebbc3e0101a6c0edcc95dc9678ee0bb58f737e17695416d08b62f62c76a2a05c41a8eb656aa01"
        await document.connect(accounts[2]).deleteController(did, did, sig2);
        // read context
        expectedJson = `["did:hsk:3c44cdddb6a900fa2b585dd299e03d12fa4293bc"]`
        json = await document.connect(accounts[2]).readController(did);
        expect(json).equal(expectedJson);
    })
    
    it("Should be able to read VerificationMethod", async () => {
        let did = "did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8";
        let expectedJson = `[{"id":"did:example:123456789abcdefghi#keys-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:example:123456789abcdefghi","publicKeyHex":"034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300"}]`
        let json = await document.connect(accounts[1]).readVerificationMethod(did);
        expect(json).equal(expectedJson);
    })

    it("Should be able to add/read/delete VerificationMethod", async () => {
        // add 
        let did = "did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8";
        let VMId = "did:example:123456789abcdefghi#keys-2";
        let VMType = "EcdsaSecp256k1VerificationKey2020";
        let controller = "did:example:123456789abcdefghi";
        let pkType = "publicKeyHex";
        let pkValue = "034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300";
        let sig = "0x71ff360f26de818058db50fdab06936d9a2c2043ec53cc95bb98d767ca2a190b70324314c4ae11a43f7546b0b973cd4940fc858aeb207d42d370312c0ed03f8700"
        await document.connect(accounts[1]).operateVerificationMethod(did, VMId, VMType, controller, pkType, pkValue, sig);
        // read
        let expectedJson = `[{"id":"did:example:123456789abcdefghi#keys-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:example:123456789abcdefghi","publicKeyHex":"034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300"},{"id":"did:example:123456789abcdefghi#keys-2","type":"EcdsaSecp256k1VerificationKey2020","controller":"did:example:123456789abcdefghi","publicKeyHex":"034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300"}]`
        let json = await document.connect(accounts[1]).readVerificationMethod("did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8");
        expect(json).equal(expectedJson);
        // delete
        await document.connect(accounts[1]).deleteVerificationMethod(did, VMId, sig);
        // read
        expectedJson = `[{"id":"did:example:123456789abcdefghi#keys-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:example:123456789abcdefghi","publicKeyHex":"034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300"}]`
        json = await document.connect(accounts[1]).readVerificationMethod("did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8");
        expect(json).equal(expectedJson);
    })

    it("Should be able to add/read/delete authentication", async () => {
        // add authentication
        let did = "did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8";
        let VMId = "did:example:123456789abcdefghi#keys-1";
        let sig = "0x71ff360f26de818058db50fdab06936d9a2c2043ec53cc95bb98d767ca2a190b70324314c4ae11a43f7546b0b973cd4940fc858aeb207d42d370312c0ed03f8700"
        await document.connect(accounts[1]).addAuthentication(did, VMId, sig);
        // read authentication
        let expectedJson = `["did:example:123456789abcdefghi#keys-1"]`
        let json = await document.connect(accounts[1]).readAuthentication(did);
        expect(json).equal(expectedJson);
        // delete authentication
        await document.connect(accounts[1]).deleteAuthentication(did, VMId, sig);
        // read authentication
        expectedJson = `[]`
        json = await document.connect(accounts[2]).readAuthentication(did);
        expect(json).equal(expectedJson);
    })
    
    it("Should be able to add/read/delete assertion", async () => {
        // add assertion
        let did = "did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8";
        let VMId = "did:example:123456789abcdefghi#keys-1";
        let sig = "0x71ff360f26de818058db50fdab06936d9a2c2043ec53cc95bb98d767ca2a190b70324314c4ae11a43f7546b0b973cd4940fc858aeb207d42d370312c0ed03f8700"
        await document.connect(accounts[1]).addAssertion(did, VMId, sig);
        // read assertion
        let expectedJson = `["did:example:123456789abcdefghi#keys-1"]`
        let json = await document.connect(accounts[1]).readAssertion(did);
        expect(json).equal(expectedJson);
        // delete assertion
        await document.connect(accounts[1]).deleteAssertion(did, VMId, sig);
        // read assertion
        expectedJson = `[]`
        json = await document.connect(accounts[2]).readAssertion(did);
        expect(json).equal(expectedJson);
    })
    
    
    it("Check did format", async () => {
        let did1 = "did:hsk:b9c5714089478a327f09197987f16f9e5d936e8a";
        expect(await document.connect(accounts[1]).checkDidFormat(did1)).true;
        let did2 = "did:hsk:b9c5714089478a327f09197987f16f9e5d936e8aa";
        expect(await document.connect(accounts[1]).checkDidFormat(did2)).false;
        let did3 = "did1:hsk:b9c5714089478a327f09197987f16f9e5d936e8a";
        expect(await document.connect(accounts[1]).checkDidFormat(did3)).false;
        let did4 = "did:hsk:b9c5714089478a327f09197987f16f9e5d936e8A";
        expect(await document.connect(accounts[1]).checkDidFormat(did4)).false;
        let did5 = "did:hsk:b9c57140894#8a327f09197987f16f9e5d936e8a";
        expect(await document.connect(accounts[1]).checkDidFormat(did5)).false;
    })

    it("Should be able to read Document", async () => {
        
        let did = "did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8";
        let sig = "0x71ff360f26de818058db50fdab06936d9a2c2043ec53cc95bb98d767ca2a190b70324314c4ae11a43f7546b0b973cd4940fc858aeb207d42d370312c0ed03f8700"
        // add controller
        let controller = "did:hsk:3c44cdddb6a900fa2b585dd299e03d12fa4293bc";
        await document.connect(accounts[1]).addController(did, controller, sig);
        // add VM
        // add 
        let VMId = "did:example:123456789abcdefghi#keys-2";
        let VMType = "EcdsaSecp256k1VerificationKey2020";
        controller = "did:example:123456789abcdefghi";
        let pkType = "publicKeyHex";
        let pkValue = "034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300";
        await document.connect(accounts[1]).operateVerificationMethod(did, VMId, VMType, controller, pkType, pkValue, sig);
        

        // add assertion
        let VMId1 = "did:example:123456789abcdefghi#keys-1";
        await document.connect(accounts[1]).addAssertion(did, VMId1, sig);
        // add auth
        let VMId2 = "did:example:123456789abcdefghi#keys-2";
        await document.connect(accounts[1]).addAuthentication(did, VMId2, sig);

        // let expectedJson = `{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8","controller":["did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8"],"verificationMethod":[{"id":"did:example:123456789abcdefghi#keys-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:example:123456789abcdefghi","publicKeyHex":"034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300"}],"authentication":[],"assertionMethod":[]}`
        let json = await document.connect(accounts[1]).resolve("did:hsk:70997970c51812dc3a010c7d01b50e0d17dc79c8");
        // expect(json).equal(expectedJson);
        console.log(json);
    })
});