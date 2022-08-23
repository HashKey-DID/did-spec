require("@nomicfoundation/hardhat-toolbox");
require('hardhat-deploy');
require('dotenv').config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
    solidity: {
        version: "0.8.16",
        settings: {
            optimizer: {
                enabled: true,
                runs: 200
            }
        }
    },
    networks: {
        localhost: {
          // accounts: { mnemonic: process.env.mnemonic },
          chainId: 1337
        },
        goerli: {
          url: "https://goerli.infura.io/v3/34c589330dc4487aad79d68d75d780c9",
          accounts: [process.env.goerli_pri],
          from: "0x425A0CB30cE4a914B3fED2683f992F8B7C9e9214",
          gas: 6000000000,
          gasPrice: 80000000000,  // 20 gwei (in wei) (default: 100 gwei)
        },
        platon: {
            // url: "http://35.247.155.162:6789",
            url: "https://devnetopenapi.platon.network/rpc",
            accounts: [process.env.platon_pri],
            from: "0x425A0CB30cE4a914B3fED2683f992F8B7C9e9214"
        },
    },
    paths: {
        sources: "./contracts",
        tests: "./test",
        cache: "./cache",
        artifacts: "./artifacts"
    },
    etherscan: {
        apiKey: {
          goerli: process.env.EHTERSCAN_API_KEY
        }
    },
    mocha: {
        timeout: 40000
    },
    namedAccounts: {
        deployer: {
          default: 0,
        },
    },
};
