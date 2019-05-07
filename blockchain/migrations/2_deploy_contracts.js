var StringUtils  = artifacts.require("./StringUtils.sol");
var SiteDeface  = artifacts.require("SiteDeface");
var PublicLeaks  = artifacts.require("PublicLeaks");
var KeyTheft  = artifacts.require("KeyTheft");

module.exports = function(deployer){

    deployer.deploy(StringUtils);
    deployer.link(StringUtils, SiteDeface);

    deployer.deploy(SiteDeface);
    deployer.deploy(PublicLeaks);
    deployer.deploy(KeyTheft);
}