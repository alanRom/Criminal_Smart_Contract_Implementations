pragma solidity ^0.5.0;

// accept
// ["0xe09ddc92f7aba0ca30ad4605055e0d61738aad08095080e96224833d93e96135","0x79d8c8c548e9cd2ca8a064d2ced06cb193981da1ac7bde34332e24b678b8b58b"]

//confirm 
// ["0x6f22768ff041f8d524077b6d5a2f3cf789d58ba4618126a6a5fd3a349e018bfd", "0x82ce375248fcab94c5d313cd09ff103d0fdeee2ec6b5971e437c78c6b15c0f50"]

// create
// ["0x9520335e658518ac5de69b857048787de0938cbe80614753996fe80e39c9059b","0x738b42fe11f36c436e4bdf585d92a109ab0d4ff2dd747e10c36a7fa05fe40421","0xc67a1c257bac3a2f8590dfb5b5d9d9761bdec7a2657f6bcc59899a059523b627", "0x2f6af6315fb0c183a950b2934a503f97aabfbf6e5da674ceac019736391e9909"]


/**
 * Contract to leak a secret in return for donations. In this case the leaked secrets are private keys
 * This follows the implementation in the paper. It was translated to solidity so it is different 
 * 
 * Assumptions: 
 * - The keys used are ethereum public keys
 * - The leaker reveals the keys in the order that he posts them
 * - The confirmed keys are assumed checked for correctness off chain  
 * 
 */
contract PublicLeaks {
  
  // struct to hold the idx value
  // this is simulating the random indicies which solidity isn't capable of
  struct Idx {
      bytes32 key;
      uint256 idx;
      uint value;
  }
  
  // the state that the contract is in
  uint state; // 0 - init, 1 - created, 2 - confirmed, 3 - aborted
  
  // the address of the leaker
  address leakerAddress;
  
  // the hashes of the keys to be leaked
  bytes32[] keyHashes;
  
  // the size of the key set to be revealed
  uint256 revealedSetSize;
  
  // a mapping of the users to the donation that they have set
  // to get the leaker to leak the keys
  mapping(address => uint) donations;
  
  // the block number of this block
  uint revealBlockNumber;
  
  // the end of how long the leaker has to leak the keys
  uint256 tEnd;
  
  // the leakers deposit
  uint deposit;
  
  // the number of keys that were committed to be revealed
  uint numChunks;
  
  // the sample of keys that were revealed in confirm
  Idx[] selectedSample;
  
  // the number of users who have donated
  uint256 numDonors;
  
  // the sum of the donations from the users 
  uint256 sumDonations;
  
  // flag for if the leak has been finalized
  uint finalized;
  
  /**
   * Empty constructor
   */ 
  constructor() public {}
  
  /**
   * Modifier to check if the caller is the leaker. Reverts if its not
   */ 
  modifier isLeaker() {
      require(msg.sender == leakerAddress, "Must be invoked by the leaker");
      _;
  }
  
  /**
   * Checks if the contract is in the correct state for the method to be called.
   * Reverts if it isnt
   */
  modifier assertState(uint inState) {
      require(state == inState, "Not in the required state to call this function");
      _;
  }
  
  /**
   * Checks if create can be called
   */
  modifier checkCreate(bytes32[] memory kh, uint256 rss) {
      // reverts if the message value is not large enough
      require(msg.value >= 1000000, "Needs a higher deposit");
      
      // reverts if the leaker has already made a deposit
      require(deposit == 0, "Leaker should not have already made a deposit");
      
      // reverts if the number of samples the leaker will reveal is less than the 
      // number of key hashes he is leaking 
      require(rss < kh.length, "Revealed sample must be less than key hash length");
      _;
  }
  
  /**
   * Checks if the user has already donated
   */
  modifier hasDonated() {
      require(donations[msg.sender] > 0, "Message sender has not donated");
      _;
  }
  
  /**
   * Checks if the sample length is the same as the set size promised to be revealed
   */ 
  modifier checkSampleLength(bytes32[] memory sampledKeys) {
    require(sampledKeys.length == revealedSetSize, "Sample keys doesnt match the size the leaker commited to");    
    _;
  }
  
  /** 
   * Checks if the users can still donate to the leak
   */
  modifier checkIfNotEnded() {
    require(now <= tEnd, "Time has already ended");
    _;
  }
  
  /**
   * Makes sure the donation is greater than 0
   */
  modifier checkDonation() {
      require(msg.value > 0, "Donation must be greater than 0");
      _;
  }
  
  /** 
   * Checks if the user has already donated
   */
  modifier alreadyDonated() {
      require(donations[msg.sender] == 0, "User has already donated");
      _;
  }
  
  /**
   * Checks if the leak has been finalized
   */
  modifier isFinalized() {
      require(finalized == 0, "Leak is already finalized");
      _;
  }
  
  /**
   * Checks if the remaining keys to be leaked matches the size that the leaker promised to reveal
   */
  modifier checkSentSize(bytes32[] memory remainingKeys) {
      require(remainingKeys.length == (numChunks - revealedSetSize), "Wrong length of remaining keys imported");
      _;
  }
  
    /**
   * Function to initialize the leak.
   * This must be called by the leaker
   */
  function init() public {
      state = 0;
      leakerAddress = msg.sender;
      deposit = 0;
      finalized = 0;
  }
  
  /**
   * Creates a leak. The leaker sets the keys that he will leak to the 
   * public in exchange for donations. He sets the number of keys that he will 
   * reveal to confirm that he has the keys
   * 
   * kh - the hashes of the keys that the leaker will leak
   * rss - the size of the keys that the leaker will revealed
   * rbn - the revealed block number
   * te - the end time of the leak
   * msg.value - the deposit that the leaker sets 
   * 
   * Modifiers: (reverts if any method is called)
   * - The address that calls this method must be the leaker
   * - Checks if the deposit is high enough
   * - Checks if the leaker has already made a deposit
   * - Makes sure that the revealed set size is less than the number of key hashes
   * - Checks if the contract is in state init
   */
  function create(bytes32[] memory kh, uint256 rss, uint rbn, uint256 te) payable public isLeaker() checkCreate(kh, rss) assertState(0) {
      // validates that create has been called
      state = 1;
      
      // sets the deposit
      deposit = msg.value;
      
      // sets the 
      numChunks = kh.length;
      
      // sets the number of keys that will be revealed in confirm
      revealedSetSize = rss;
      
      // sets the timeout for the leak
      tEnd = te;
      
      // sets the revealed block number
      revealBlockNumber = rbn;
      
      // adds the keys to the array of key hashes
      uint256 i = 0;
      while (i < kh.length) {
          keyHashes.push(kh[i]);
          i = i + 1;
      }
  }
  
  /**
   * Leaker reveals the number of keys that they set in revealed set size. This is to confirm that
   * the leaker actually has valid keys to revealed. The storage simulates storing at random
   * indicies, which is not supported in solidity
   * 
   * Assumption: Keys are checked for correctness off chain 
   * 
   * - sampledKeys: the list of keys to be revealed
   * 
   * Modifiers: (Reverts if conditions arent met)
   * - Checks if the caller is the leaker
   * - Checks if the length of the sample keys that were sent in is equal to the number that they promised to revealedSetSize
   * - Checks if the create method has been called
   */
  function confirm(bytes32[] memory sampledKeys) public isLeaker() checkSampleLength(sampledKeys) assertState(1) {
        // gets the seed from the blockhash
        int256 seed = int256(blockhash(block.number));
        
        // counter variable
        uint256 c = 0;
        
        // subtracts seed from 0
        seed = 0 - seed;
        
        // do this for every key
        while (c < revealedSetSize) {
            // make sure the seed is negative
            if (seed < 0) {
                seed = 0 - seed;
            }
            
            // sets the idx
            uint256 idx = uint256(seed % int256(numChunks));
        
            // sets while loop flags
            bool flag = true;
            bool found = false;
            
            // the second counter
            uint c2 = 0;
            
            while(c2 < selectedSample.length) {
                // makes sure the idx was not selected more than once 
                if (selectedSample[c2].idx == idx) {
                    found = false;        
                }
                
                c2 = c2 + 1;
            }
            
            if (found == false) {
                flag = false;
            }
        
            // recompute the idx if it was already used 
            while(flag == true) {
                
                // recompute the seed
                seed = int256(keccak256(abi.encodePacked(bytes32(seed))));
                
                // makes sure the seed is negative 
                if (seed < 0) {
                    seed = 0 - seed;
                }
                
                // compute the idx from the seed
                idx = uint256(seed % int256(numChunks));
                
                // checks if the new idx wasnt already set 
                uint c3 = 0;
                found = false;
                while(c3 < selectedSample.length) {
                    if (selectedSample[c3].idx == idx) {
                        found = true;        
                    }
                    c3 = c3 + 1;
                }
                
                // stop if the idx was not already used 
                if (found == false) {
                    flag = false;
                }
            }
            
            // creates the idx object 
            Idx memory temp;
            temp.key = sampledKeys[c];
            temp.idx = idx;
            temp.value = 1;
            
            // adds it to the array 
            selectedSample.push(temp);
        
            // recompute the seed
            seed = int256(keccak256(abi.encodePacked(bytes32(seed))));
            
            // increment the counter
            c = c + 1;
        }
        
        // set the state to confirmed
        state = 2;
  }
  
  /**
   * Users send donations to the leaker so that he will leak the keys. The leaker will
   * leak the keys if there is enough donations. Users can only make donations if the 
   * the leak has been confirmed
   * 
   * - msg.value The deposit that the user seconds
   * 
   * Modifiers:
   * - Checks if donations can still be made 
   * - Asserts that confirm has been called
   */
  function donate() public payable checkIfNotEnded() assertState(2) {
      
      // sets the donations for the users 
      donations[msg.sender] = msg.value;
      
      // increments the number of donars
      numDonors = numDonors + 1;
      
      // inrements the sum of the donations 
      sumDonations = sumDonations + msg.value;
  }
  
  /**
   * The leaker accepts the donations by revealing all of the keys. If the keys that the leaker
   * sends in dont match the key hashes then the leaker does not get the reward
   * 
   * Assumptions: The leaker sends in the keys in the order that he posted them
   * 
   * -remainingKeys: The rest of the keys to be leaked
   * 
   * Modifiers:
   * - Checks if the size of the keys sent in is equal to the number of keys left to be revealed
   * - Checks if the time to leak is not over 
   * - Checks if the leaker called this method
   * - Checks if the leak has already been finalized
   */
  function accept(bytes32[] memory remainingKeys) public checkSentSize(remainingKeys) checkIfNotEnded() isLeaker() isFinalized() {
    // sets the counts
    uint idx1 = remainingKeys.length - 1;
    uint idx2 = keyHashes.length - 1;
    
    // if any of the keys dont match, valid gets set to 0 
    uint valid = 1;
    
    // checks if the keys match 
    while (valid == 1 && idx1 < remainingKeys.length) {
       // gets the key and hashes it
        bytes32 key = keccak256(abi.encodePacked(remainingKeys[idx1]));
        
        // gets the corresponding key 
        bytes32 keyHash = keyHashes[idx2];
        
        // checks if the keys are equal.
        if (key != keyHash) {
            valid = 0;
        }
        
        // decrements the counter 
        if ((idx1 - 1) >= 0 && (idx2 - 1) >= 0) {
            idx1 = idx1 - 1;
            idx2 = idx2 - 1;    
        }
    }

    // if all the keys match 
    if (valid == 1) {
        // transfer the donations to 
        msg.sender.transfer(sumDonations + deposit);
       
        // sets the leak to finalized
        finalized = 1;

        // sets the state to accepted 
        state = 3;
    } 
  }
  

  /**
   * Timer function to give the donors their money back if the leak is never finalized
   * in a reasonable amount of time. This is called by an individual donor in order to get 
   * only their money back 
   * 
   * Modifiers: 
   * - makes sure the leak has not already been finalized
   */
  function timer() public isFinalized() {
    // calculates the donors donation and their share of the deposit
    uint send = donations[msg.sender] + deposit / numDonors;
    
    // sends the donor their donation back 
    msg.sender.transfer(send);
  }
  
  // helper functions for testing
  
  /**
   * Returns the current time in the blockchain. Using this makes sure 
   * That there is no time disconnect
   */
  function returnTimestamp() public view returns (uint256) {
      return now;
  }
  
  /**
   * Returns the current block number 
   */
  function returnBlockNum() public view returns (uint256) {
      return block.number;
  }
  
  /**
   * Hash function for the keys 
   */
  function hash(bytes32 b) public pure returns (bytes32) {
      return keccak256(abi.encodePacked(b));
  }
  
  /**
   * Returns if the leak has been finalized
   */
  function getFinalized() public view returns(uint256) {
      return finalized;
  }
}

// example

// key 1 f742ce7715bd886d980242168f2dff372b8fb44d50abfdd122da43075f1a77ca
// key2 2a06265b194a95beb0b8edd24baeccc221bced22176ef1bfffa529fcc160838a
// key3 b9c68c86600fbb317e42e44f1a6d81ae2444468ffcb8badff6c575fe76bd455c
// key4 6b3d18db528ac7ea566b04b1a40a1ffa6749761ffc9bbb9d918a2d3716ad6a39

// create

//["0xc0f9f5b17d6afe6c5ea9be106bea3b9275a55a1a25b2009ff3e6f5571f794c95", "0x73426b752f2ea2bd9aca6c78cc4a7a3ef8855bb060e3d346f72c0be450aa9da0", "0x138277bffedec1ca59336a042f16a04632472f16c2837723d9358b2dc3233b77", "0xb7cc155a5895dfdb143215a182c1505fcd91142a5ae82d4f7ecdd93aa87745e2"]


// confirm
//["0xf742ce7715bd886d980242168f2dff372b8fb44d50abfdd122da43075f1a77ca", "0x2a06265b194a95beb0b8edd24baeccc221bced22176ef1bfffa529fcc160838a"]

// accept
//["0xb9c68c86600fbb317e42e44f1a6d81ae2444468ffcb8badff6c575fe76bd455c", "0x6b3d18db528ac7ea566b04b1a40a1ffa6749761ffc9bbb9d918a2d3716ad6a39"]