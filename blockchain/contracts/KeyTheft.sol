/*
{
	"proof":
	{
		"A":["0x2ee1d7ecd571a13bf7384db25e40a52b0e96dd5212188269c53e3bc898b27b4e", "0x2adb91e740459fe137387cc0c33574d997686c5cdd0d8f391e5eeb0a3fa9249b"],
		"B":
			[["0x1a20c5d9a884a60da465920519673efe4ea02063dde181a52533e6761d9a3bc2", "0x1a83d0b4d7fa0c09c26f67d73faee0758c1260c6644291cd2c725d42bbf49ddb"], ["0x03cbf9d757acda3ff9a120e97b9e0e2fb8c1ea2be532e0a9a21262ee2941616a", "0x2ebe24ed81fac8f6bc5de7717d72da6c781b84acefd995db2cd5676e9ce2dd46"]],
		
		"C":["0x1fc53f2db23b2c03c6a75f7fa3988600d042ddd91f64b6d757888d834a6786f8", "0x2291034cc586cd083ad298a69c27c830a6c19f5f81c8867c359fa618eb1bf4c8"],
	},
	"input":["0x1372871792bc1de9cdd1a2cd4d970a650667d03afa3a97203b80880a95704b9a","0x209155e1158b32899c8f7c19f40c07c26aaf85eef95695074b8f62e5829361c1","0x000000000000000000000000a0f78e4dde0f398130591e53e6a13ec3e19d6b7b","0x0000000000000000000000000000000000000000000000000000000000000001"]
}

*/

pragma solidity >=0.4.24 <0.6.0;
pragma experimental ABIEncoderV2;

/**
 * Contract to post public keys that the contractor is looking for, and a perpetrator steals the key (off chain)
 * and gives it to the contractor in exchange for money
 * 
 * Assumptions: 
 * - The keys pairs are keys generated for eddsa 
 * - The keys are verified for correctness off chain (by the zk-snark code)
 */
contract KeyTheft {
    
    // struct to store information about the perpetrator 
    struct p {
        
        // perpetrators payable address
        address payable perpAddress;

        // flag if the intent has already been sent 
        bool sentIntent;
        
        // the perpetrators commit 
        bytes32 commit;
    }
    
    // A struct for our proof of work used to validate the key. Parameters are stored on chain 
    // generated from out zk-snark 
    struct Proof {
        uint[2] a;
        uint[2][2] b;
        uint[2] c;
        uint[4] input;
    }
    
    // A struct to store the verifiying key from our proof of work
    struct VerifyingKey {
        uint256[2][2] h;
        uint256[2] galpha;
        uint256[2][2] hbeta;
        uint256[2] ggamma;
        uint256[2][2] hgamma;
        uint256[2] query0;
        uint256[2] query1;
        uint256[2] query2;
        uint256[2] query3;
        uint256[2] query4;
    }

    // the verifying key values (hardcoded in constructor since its always the same)
    VerifyingKey verifyingKey; 
    
    // the users parameters from the valid zk-snark proof 
    Proof verificationParams;
    
    // the contractors address 
    address payable contractor;
    
    // the reward that the contractor sets 
    uint256 reward;
    
    // the small reward if a user finds a revoked key
    uint256 smallReward;
    
    // The public key of the private key the contractor is looking for 
    bytes[] publicKey;
    
    // the timeout of the contract 
    uint256 tEnd;
    
    // the state that the contract is in 
    uint state; //init = 0, created = 1, claimed = 2, aborted = 3
   
    // the perpetrator
    p perpetrator;
    
    // the time since the last successful claim 
    uint256 timeSinceClaim;
    
    /**
     * Checks if the caller of the function is the contractor
     */
    modifier isContractor() {
        require(msg.sender == contractor, "Function can only be invoked by contractor");
        _;
    }
    
    /**
     * Checks if the reward is greater than the hardcoded small reward
     */
    modifier assertReward() {
        require(msg.value > 5000, "Reward must be greater than the small reward");
        _;
    }
    
    /**
     * Asserts the state of the Contract
     */
    modifier assertState(uint stateNum) {
        require (state == stateNum, "Contract is not in the correct state");
        _;
    }
    
    /** 
     * Asserts that the perpetrator has not sent the intent yet 
     */
    modifier assertPerpetrator() {
        require(perpetrator.sentIntent == false, "Perpetrator already sent intent");
        _;
    }
    
    /**
     * Checks if the invoker is the perpetrator
     */
    modifier isPerpetrator() {
        require(perpetrator.perpAddress == msg.sender, "This is not the perpetrator");
        _;
    }
    
    
    /**
     * Asserts that the perpetrator has not sent the intent yet
     */
    modifier assertPerpetratorIntent() {
        require(perpetrator.sentIntent == true, "Perpetrator did not already send intent");
        _;
    }
    
    /**
     * Instantiates the contract instance
     */
    constructor() public payable {
        
        // hard codes the small reward 
        smallReward = 5000;
    
        // hard codes the verifying key for our zk-snark. This will be the same for every contract that uses are proof 
        verifyingKey.h = [[uint256(0x1f6a6036b6e03208032a7134481379ddcc61af4712987489aa61d49c681c6429), uint256(0x0e4d68a7c445943f90e851c42fd5d823f8cacc099d9e4650123fb054e629d018)], [uint256(0x2d52f866287d977b5191642b830ce3855a38d929d9488f8a1a8db04c55850a9b), uint256(0x07ca457d1688c418a4da106f03d0454d6b174427ee2376944eb7c8470261c8b)]];
        verifyingKey.galpha = [uint256(0x206e47bbcc3b1abce1d41019fd23f0281366b4de7dabc8e7b851278cfd27dc07), uint256(0x20b9ec36d27325d141c4248984552377a44be05685710f04bcd1bc3281fd0d71)];
        verifyingKey.hbeta = [[uint256(0x1243e00f57bd7922e87bd2039e27f38bf3a9aa2a99d63fb808fc1fdcb2a8d3f8), uint256(0x022bcdfd238618b9b7fcaf2f76864cccd64ef7acfafb38e0380ee4d1536733dc)], [uint256(0x0166392d6003ab584793e2c6e9d6e51c89f7fe9df81073c9a9560a2778d3566f), uint256(0x04d4131d730a84b8406634a488224e5035922dd211f22b8efe4d0c0024b277f9)]];
        verifyingKey.ggamma = [uint256(0x13dc96e609e4ef378244e7a1c24a3f14d111cee7f3716eef42480b7a11dcf4a9), uint256(0x1fe8597df989f8c5e1113f07f895253c604d8dbea24fef6de8463c59b1182a36)];
        verifyingKey.hgamma = [[uint256(0x0a45b94f15d0ade9fe6d445167c84a73af1c67f642b77bfaf2bc721622c4b7a1), uint256(0x22ac7e1436c3a496c56f02834f47fb375d1fe065720790053bdad229a707e9d5)], [uint256(0x192caaf71e893c17f520115c255973ede1585ed03e0e70d1ae1b0e03326887e6), uint256(0x01df7ead07969aae67871c957fcbf771993a84e6946e8eb0a2ac929698c61f34)]];
        verifyingKey.query0 = [uint256(0x132f9a65546faca0c6cd90aaa3c6a50632f66a9706f3a1a94f147a497a246c95), uint256(0x06f5b728dc8d3121615fc6735091d86f807e432b55eb590a83cd0923c2a31b5d)];
        verifyingKey.query1 = [uint256(0x05b803867d09213e7eafb04d7cbd06dcbbc30ec146296541a4c570c1b373d7d4), uint256(0x03cb7b16f8bc88655b6e1264207c99d6b37a391d25228be4e7696b5ab0b1ad3d)];
        verifyingKey.query2 = [uint256(0x2d9baaf742cd91040e3cd5513cb22ac3900888bbbf5fec46cc74465451c2802c), uint256(0x2507890328edc46335c0c32b86cb3bfb2f5423c3758493016558e89893476d46)];
        verifyingKey.query3 = [uint256(0x2f69e1c90b951f4c85526a062adcf782026e0429aa1222ae7f4229ce5aa9a30b), uint256(0x1ace5f0cbe5376a6290d13c22186a8ea98893f76cbd89b816758dcc31ddb376b)];
        verifyingKey.query4 = [uint256(0x05271a3c626f93e28b981b2572511e1043b613ff04bf1957a240ad453a3d82d4), uint256(0x026b81aa88d08aa7e0e22329e0e5867736395ea13855c834814544543e8aa65b)];
    }
    
    /**
     * Initializes the contract with a contractor
     */
    function init() public {
        // the contractor 
        contractor = msg.sender;
        
        // sets the state to init 
        state = 0;
    }
    
    /**
     * Sets the public key of the private key the contract is looking for and sets a timeout 
     * 
     * Assumptions: 
     * - The key pairs are eddsa key pairs 
     * 
     * - pubkey The public keys 
     * - tend The timeout of the contract
     * - msg.value Reward for finding the secret key 
     * 
     * Modifiers:
     * - The reward must be greater than the small reward
     * - This method can only be called by the contractor
     * - Init must have already been called 
     */
    function Create(bytes[2] memory pubKey, uint256 tend) public payable assertReward() isContractor() assertState(0) {
        // sets the keys 
        publicKey = pubKey;
        
        // sets the timeout 
        tEnd = tend;
        
        // sets the reward 
        reward = msg.value;
        
        // sets the state to created 
        state = 1;
    }
    
    /**
     * Sets the perpetrator that intends to find the secret key
     * 
     * Assumptions: 
     * - sends in a commit that is a valid hmacsha256 
     * 
     * - commitment The commitment that the perpetrator will find the key
     * - msg.sender The perpetrator 
     * 
     * Modifiers: 
     * - Makes sure create has already been called
     * - Checks if the perpetrator has not already been set 
     */
    function intent(bytes32 commitment) public assertState(1) assertPerpetrator() {
        // sets the address of the perpetrator 
        perpetrator.perpAddress = msg.sender;
        
        // validates that the perpetrator sent the intent 
        perpetrator.sentIntent = true;
        
        // the perpetrators commitment 
        perpetrator.commit = commitment;
    }
    
    /** 
     * The perpetrator can claim the reward if the secret keys match. This is done using the zk-snark proof off 
     * chain. It can be verified by anyone that it is a valid proof by verifying the proof with parameters
     * 
     * Assumptions: 
     * - The keys are validated off chain 
     * 
     * ct: The key used for the commitment 
     * r: The message used for commitment 
     * a, b, c, input: the parameters used for 
     * 
     * Modifiers: 
     * - Asserts that there was a created private key to steals
     * - Asserts that the perpetrator set the intent
     * - Asserts that the caller is the perpetrator 
     */
    function claim(bytes memory ct, bytes memory r, uint[2] memory a, uint[2][2] memory b, 
        uint[2] memory c, uint[4] memory input) public assertState(1) assertPerpetratorIntent() isPerpetrator(){
        
        // calculates the commitment 
        bytes32 cm = _hmacsha256(r, ct);
        
        // checks if the sent commitment is equal to the perpetrators committment 
        require(cm == perpetrator.commit, "The commitment for this claim does not match the intent");
        
        // sets the verification parameters to that they are visible on the blockchain 
        verificationParams.a = a;
        verificationParams.b = b;
        verificationParams.c = c;
        verificationParams.input = input;
        
        // sets the state to claimed
        state = 2;
    }
    
    /**
     * Prevents a revoke and claim attack. If the certificate for the keys have been revoked then 
     * the perpetrator will not get the full reward
     * 
     * Assumptions: 
     * - We could not get a valid revocation list because of test data so we made our own by  creating a 
     *   list of keys. Since 2D arrays are not fully implemented and correct in solidity (they are the reason
     *   for the experimental encoder), they are a list of the first keys and the second keys, and are assumed to 
     *   pairs at every index number 
     * 
     * revokedKeys1: The list of keys of the first keys 
     * revokedKeys2: The list of keys of the second keys 
     */
    function revoke(bytes[] memory revokedKeys1, bytes[] memory revokedKeys2) public {
        
        // The list of the revoked keys sizes must match 
        require(revokedKeys1.length == revokedKeys2.length, "revokedKeys1 and revokedKeys2 should be equal in length");
        
        // counter 
        uint i = 0;
        
        // if the keys have been revoked 
        bool verify = false;
        
        // check every key 
        while(verify == false && i < revokedKeys1.length) {
            
            // gets the keys to check from the revoked key list 
            bytes memory rk1 = revokedKeys1[i];
            bytes memory rk2 = revokedKeys2[i];
            
            // gets the public key 
            bytes memory pk1 = publicKey[0];
            bytes memory pk2 = publicKey[1];
            
            // checks if they match 
            if (keccak256(abi.encodePacked(rk1)) == keccak256(abi.encodePacked(pk1)) && 
                keccak256(abi.encodePacked(rk2)) == keccak256(abi.encodePacked(pk2))) {
                verify = true;
            }
    
            // increment 
            i++;
        }
        
        // if none of the keys match, they havent been revoked, so dont continue 
        if (verify == false) revert();
        
        // transfer the small reward to the user who found the revoked key 
        msg.sender.transfer(smallReward);
        
        if (state == 2) {
            // if the key had already been claimed, give the perpetrator a reward 
            // that is a function of the time since the last claim 
            uint256 t = now - timeSinceClaim;
            perpetrator.perpAddress.transfer(reward / t);
        } else {
            // give the contractor his money back without the small reward paid to the finder 
            contractor.transfer(reward - smallReward);
        }
        
        // sets the state to aborted 
        state = 3;
    }
   
    /** 
     * Checks the time of the contract and assigns the reward based on the result
     * 
     * Modifier: 
     * Asserts that claimed was called 
     */
    function timer() public assertState(2) {
        
        // checks if the time elapsed has been long enough to get the reward
        // change hardcoded for simplicity 
        if(1000 < (now - timeSinceClaim)) {
            // sends the perpetrator the reward 
            perpetrator.perpAddress.transfer(reward);
            
            // sets the state to aborted 
            state = 3;
        } else if (now > tEnd) {
            // if the contract times out transfer the reward back to the contractor 
            contractor.transfer(reward);
            
            // set the state to aborted 
            state = 3;
        }
    }
    
    /** 
     * Helper function to make the intent 
     * 
     * ct: the key generate the hmacsha256
     * r: the message 
     */
    function MakeIntent(bytes memory ct, bytes memory r) public  pure returns (bytes32){
        return _hmacsha256(r, ct);
    }

    /** 
     * function to compute the hmacsha256 
     * 
     * Retrieved from https://ethereum.stackexchange.com/questions/64510/hmac-x-implementation-for-solidity by saman.shahmohamadi
     * 
     * key: the key to encrypt with 
     * message: the message to encrypt 
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
    
    /**
     * Helper function to get the current time
     */ 
    function GetTime() public view returns (uint256) {
        return now;
    }
    
    //["0x14897476871502190904409029696666322856887678969656209656241038339251270171395", "0x16668832459046858928951622951481252834155254151733002984053501254009901876174"]
   // return [bytes(0x14897476871502190904409029696666322856887678969656209656241038339251270171395),
     //       bytes(0x16668832459046858928951622951481252834155254151733002984053501254009901876174)];
     //["0x14897476871502190904409029696666322856887678969656209656241038339251270171395"]
     
     //["0x16668832459046858928951622951481252834155254151733002984053501254009901876174"]
     
     //0xc4cd34fdf9d78044cac20db0407ba4640d1c73f06110468f4f0544454b6626da
}




