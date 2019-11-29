pragma solidity ^0.5.11;

import "/helpers/smart_contract_chain.sol";
import "/helpers/safe_math.sol";
import "/helpers/execute_on_send.sol";
import "/helpers/ownable.sol";


// Minting has to occur on smart contract chain because that is where the owner variable is stored.
contract HeliosDelegatedToken is ExecuteOnSend, Ownable {
    using SafeMath for uint256;

    // The balance of this token on the currently executing chain.
    uint256 balance;

    // Variables for the smart contract chain.
    uint256 public constant totalSupply = 300000000 * (10 ** uint256(decimals));

    /**
    * @dev Mint tokens onto whatever chain the transaction is sent to
    * This can only be initiated from this smart contract.
    * This is usually only called in the constructor when the contract is deployed.
    */
    function mintTokens(uint256 amount) public onlyFromSmartContractChain{
        balance = balance.add(amount);
    }

    function sendMintTokens(address _to, uint256 amount) private {
        bytes4 sig = bytes4(keccak256("mintTokens(uint256)")); //Function signature
        address _this = address(this);

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,sig) //Place signature at beginning of empty storage (4 bytes)
            mstore(add(x,0x04),amount) //Place first argument directly next to signature (32 byte int256)

            let success := surrogatecall(100000, //100k gas
                                        _this, //Delegated token contract address
                                        0,       //Value
                                        0,      //Execute on send?
                                        _to,   //To addr
                                        x,    //Inputs are stored at location x
                                        0x24 //Inputs are 36 bytes long
                                        )

        }

    }

    function getBalance() public view returns (uint256) {
        return balance;
    }

    function transfer(uint256 amount) public requireExecuteOnSend {
        if(is_send()){
            // This is the send side of the transaction. Here we subtract the amount from balance.
            require(amount <= balance);
            balance = balance.sub(amount);

        }else{
            // This is the receive side of the transaction. Here we add the amount to balance.
            balance = balance.add(amount);
        }
    }



    /**
    * @dev The Ownable constructor sets the original `owner` of the contract to the sender
    * account.
    */
    constructor() public {

        // Mint the entire supply of tokens on the msg.sender's chain using a surrogatecall.
        // Here we are sending a surrogatecall transaction back to the owner. When the owner receives
        // this transaction, their balance will be increased by totalSupply
        address _this = address(this);
        address _owner = msg.sender;
        sendMintTokens(_owner, totalSupply);
    }

    // do not allow deposits
    function() public{
        revert();
    }
}