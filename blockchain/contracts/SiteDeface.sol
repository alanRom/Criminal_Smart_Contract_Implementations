pragma solidity >=0.4.24 <0.6.0;

//Library of String functions, used for indexOf function to search for substrings in the website content
import "./StringUtils.sol";

/**
 * This contract is meant to commission the defacement of a target website with a desired statement.
 * By committing to the defacement and showing proof of the crime, the perpetrator of the crime
 * will receive the reward placed by the contractor.
*/
contract SiteDeface{
    uint256 _reward; // Crime payout
    address _pk;    //Public key of the website, assumed to be an Ethereum address for proof-of-concept
    string _url;    //URL of the target webite
    string _stmt;   //Desired statement to appear on the defaced website
    uint t_start;   // Time that the contract is initialized and ready to receive claims
    mapping(bytes32 => address) vcc; //Stores a given commitment with the sender to prove 
                                     //that the perpetrator committed to the crime before claiming

    constructor() public payable{
    }

    /**
     *  Initializes the contract by storing the details of the crime
     * 
     * msg.value - the money passed to the contract to serve as the payout on a successful Claim
     * pk - the public key of the website to deface
     * url - the URL of the website to deface
     * stmt - the target string to see in the defaced website
     * 
     * Assumptions:
     * pk is in the same format as Ethereum addresses(ECDSA secp256k1)
     * 
     */
    function Init (address pk, string memory url, string memory stmt ) public payable {
        //
         require(msg.value > 50, "Reward must be non-zero");
        _reward = msg.value;
        _pk = pk;
        _url = url;
        _stmt = stmt;
        t_start = now;
    }
    
    /**
     *  Store the commitment for the current perpetrator
     *  This commitment must match the details in Claim later on 
     * 
     * vcc_i - the commitment for the crime, should be the output of MakeVCC
     */
    function Commit(bytes32 vcc_i) public  {
      
        vcc[vcc_i] = msg.sender; //Associate the commitment with the address of the sender(potential perpetrator)
    }
    

     /**
     * Helper function to make the commitment for the perpetrator. Automatically inserts their address into the commitment
     * for verification later in Claim
     * 
     * cc - the calling card for the crime
     * randomness - used to sign the HMAC generated
     */
    function MakeVCC(string memory cc, bytes memory randomness) public view returns (bytes32){
        
        //Return the hmac acting as the "commit()" function mentioned in the paper
        return _hmacsha256(randomness, abi.encodePacked(cc, msg.sender));
    }

    /**
     * Helper function to return the current time as a uint256
     */
    function GetTime() public view returns (uint256){
        
        
        return now;
    }
    
    
    /**
     *  Accepts proof of the defacement crime. Verifies the commitment to the crime and the signature of the website.
     *  Checks to make sure statement and calling card are in the website content. If all conditions are met, pays 
     *  out the reward.
     * 
     * cc - the calling card for the crime
     * randomness - random bytes to sign the HMAC/commitment
     * msgHash - output hash of the ecsign function ( signature generated off-chain )
     * _v - output parameter of the ecsign function ( signature generated off-chain )
     * _r - output parameter of the ecsign function ( signature generated off-chain )
     * _s - output parameter of the ecsign function ( signature generated off-chain )
     * content - the HTML code of the website
     * time - the time that the defacement was stated to occur at
     * 
     * Assumptions:
     * -msgHash, _v, _r, _s are obtained by using the ecsign function on the private key for the store public key _pk
     *          and generated from the tuple/concatenation of (cc,content,url,time)
     * -The paper describes using future functionality to obtain the HTML content directly from the contract.
     *  Due to limitations of the platform, it must be passed in, along with the signature meant to act as a certificate authority signature
     * 
     */
    function Claim(string memory cc, bytes memory randomness, bytes32 msgHash, uint8 _v, bytes32 _r, bytes32 _s, string memory content, uint time )  public payable{
        //Submit proof that the website has been defaced. Due to the lack of tools to make Http requests in Solidity, the content and signatures must be passed in.
        // The paper also leaves this as a task for future versions of the platform
        bytes32 claimedVcc = _hmacsha256(randomness, abi.encodePacked(cc, msg.sender));

        require(vcc[claimedVcc] != address(0), "A previous commitment for this calling card was not found. Did you remember to Commit?");
        require(StringUtils.indexOf(content, _stmt) != -1, "Statement should appear in the webpage content");
        require(StringUtils.indexOf(content, cc) != -1, "Calling card should be the preamble of the webpage content");
        require(time > t_start, "Contract hasn't started yet");

        address recoveredPublicKey = ecrecover(msgHash, _v, _r, _s); //Verify the site's signature matches the public key stored in the contract. For proof-of-concept
                                                                     // an Ethereum public key is used to leverage the built-in ecrecover() function
        
        require(recoveredPublicKey == _pk, "Signature passed did not match the public key stored");

        msg.sender.transfer(_reward); //Send the perpetrator their payment
    }
    
    
    /**
     * HMAC function used to implement the commit() function described in the paper
     * Retrieved from https://ethereum.stackexchange.com/questions/64510/hmac-x-implementation-for-solidity by saman.shahmohamadi
     * 
     * key - signing key for the HMAC
     * message - content to sign
     */
    function _hmacsha256(bytes memory key, bytes memory message) internal pure returns (bytes32) {
        bytes32 keyl;
        bytes32 keyr;
        uint i;
        if (key.length > 64) {
            keyl = keccak256(key);
        } else {
            for (i = 0; i < key.length && i < 32; i++){
                uint keyAtIndex;
                assembly {
                    keyAtIndex := mload(add(key, i))
                }
                keyl |= bytes32(keyAtIndex * 2 ** (8 * (31 - i)));

            }
            for (i = 32; i < key.length && i < 64; i++){
                uint keyAtIndex;
                assembly {
                    keyAtIndex := mload(add(key, i))
                }
                keyr |= bytes32(keyAtIndex * 2 ** (8 * (63 - i)));

            }
        }
        bytes32 threesix = 0x3636363636363636363636363636363636363636363636363636363636363636;
        bytes32 fivec = 0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c;
        return keccak256(abi.encodePacked(fivec ^ keyl, fivec ^ keyr, keccak256(abi.encodePacked(threesix ^ keyl, threesix ^ keyr, message))));
    }
}