pragma solidity ^100.5.14;

import "./helpers/smart_contract_chain.sol";
import "./helpers/safe_math.sol";
import "./helpers/execute_on_send.sol";
import "./helpers/ownable.sol";


contract HeliosDelegatedToken is ExecuteOnSend, Ownable, SmartContractChain {
    using SafeMath for uint256;

    // The balance of this token on the currently executing chain.
    uint256 balance;

    // Mapping to store the receipt of transactions
    mapping(bytes32 => bool) public receipts;

    // Variables for the smart contract chain.
    // Change these to suit your token needs!
    string  public constant name = "My new token!";
    string  public constant symbol = "token symbol";
    uint8   public constant decimals = 18;
    uint256 public constant totalSupply = 300000000 * (10 ** uint256(decimals));

    // If you are creating your own standard token, there is no need to edit anything below this line

    /**
    * @dev Mint tokens onto whatever chain the transaction is sent to
    * This can only be initiated from this smart contract.
    * This is usually only called in the constructor when the contract is deployed.
    */
    function mintTokens(uint256 amount) public onlyFromSmartContractChain{
        balance = balance.add(amount);
    }

    /**
    * @dev Create a surrogatecall transaction to send the mintTokens command
    * to a chain.
    * Be sure to leave this private so that it can only be called by this smart contract
    */
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

    /**
    * @dev Gets the balance of tokens on the currently executing chain
    */
    function getBalance() public view returns (uint256) {
        return balance;
    }



    /**
    * @dev Transfers tokens from one chain to another. This function needs to be called using a transaction
    * with execute_on_send = True
    */
    function transfer(uint256 amount) public requireExecuteOnSendTx {
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
    * @dev Same as transfer, except it saves a receipt itentifier so that other contracts
    * can check for a receipt to be sure that the transaction has arrived.
    */
    function transfer(uint256 amount, bytes32 receipt_identifier) public requireExecuteOnSendTx {
        if(is_send()){
            // This is the send side of the transaction. Here we subtract the amount from balance.
            require(amount <= balance);
            balance = balance.sub(amount);

        }else{
            // This is the receive side of the transaction. Here we add the amount to balance.
            balance = balance.add(amount);
            receipts[receipt_identifier] = true;
        }
    }

    /**
    * @dev Returns true if the transaction has been received, false otherwise
    */
    function transactionReceived(bytes32 receipt_identifier) public view returns (bool){
        return receipts[receipt_identifier];
    }

    /**
    * @dev Deletes a receipt from the mapping
    */
    function deleteReceipt(bytes32 receipt_identifier) public {
        delete receipts[receipt_identifier];
    }

    constructor() public {

        // Mint the entire supply of tokens on the msg.sender's chain using a surrogatecall.
        // Here we are sending a surrogatecall transaction back to the owner. When the owner receives
        // this transaction, their balance will be increased by totalSupply
        address _this = address(this);
        address _owner = msg.sender;
        sendMintTokens(_owner, totalSupply);
    }

    // do not allow deposits
    function() external{
        revert();
    }
}