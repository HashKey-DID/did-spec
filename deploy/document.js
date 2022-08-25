module.exports = async ({
    getNamedAccounts,
    deployments,
}) => {
const {deploy} = deployments;
const {deployer} = await getNamedAccounts();
console.log(`>>> your address ${deployer}`);

await deploy('Document', {
    from: deployer,
    args: [],
    log: true,
    waitConfirmations:1,
});
};

module.exports.tags = ["Document"];