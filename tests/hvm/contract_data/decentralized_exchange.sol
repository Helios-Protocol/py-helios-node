pragma solidity ^100.5.11;

import "./helpers/smart_contract_chain.sol";
import "./helpers/safe_math.sol";
import "./helpers/execute_on_send.sol";
import "./helpers/ownable.sol";


contract Token {
    function getBalance() public view returns (uint256);
    function transactionReceived(bytes32 receipt_identifier) public returns (bool);
}

// Minting has to occur on smart contract chain because that is where the owner variable is stored.
contract DecentralizedExchange is Ownable {
    using SafeMath for uint256;

    struct PendingDepositInfo {
        uint256 amount;
        bytes32 receipt_identifier;
    }

    mapping(address => mapping(address => PendingDepositInfo[])) public pending_deposits; // wallet address -> token contract (0 for HLS) -> list of pending deposits for that contract.
    mapping(address => mapping (address => uint)) public tokens; //mapping of token addresses to mapping of account balances (token contract = 0 means HLS)

    uint256 deposit_nonce;

    function depositTokens(address exchange_deposit_address, address token_contract_address, uint256 amount) public requireExecuteOnSendTx{
        if(is_send()){
            // Lets make sure they have enough balance on this chain. They could potentially spend the balance before
            // the transaction is sent, resulting in an error, but that is why we use a receipt identifier to know
            // if it was received or not.
            uint256 token_balance_on_this_chain = Token(token_address).getBalance();
            require(amount <= token_balance_on_this_chain);

            // Send the transaction
            bytes4 sig = bytes4(keccak256("transfer(uint256,bytes32)")); //Function signature
            assembly {
                let x := mload(0x40)   //Find empty storage location using "free memory pointer"
                mstore(x,sig) //Place signature at beginning of empty storage (4 bytes)
                mstore(add(x,0x04),amount) //Place first argument directly next to signature (32 byte int256)
                mstore(add(x,0x24),receipt_identifier) //Place second argument next to it (32 byte bytes32)

                let success := surrogatecall(100000, //100k gas
                                            token_contract_address, //Delegated token contract address
                                            0,       //Value
                                            1,      //Execute on send?
                                            exchange_deposit_address,   //To addr
                                            x,    //Inputs are stored at location x
                                            0x44 //Inputs are 4 + 32 + 32 = 68 bytes long
                                            )
            }

        }else{
            // Here lets check if it was already received, if so lets just add it to the balance
            bool is_transaction_received = Token(token_address). transactionReceived(receipt_identifier);
            if(is_transaction_received){
                // it has already been received
                tokens[msg.sender][token_contract_address].add(amount);
            }else{
                // it has not been received
                pending_deposits[msg.sender][token_contract_address].push(
                    PendingDepositInfo({
                        amount: 0,
                        receipt_identifier: receipt_identifier
                    })
                );
            }

        }
    }

//    function checkTransactionReceived(bytes32 receipt_identifier) public view returns (uint256){
//        pass;
//    }

    function getTokenBalance(address token_address) public view returns (uint256){
        // This will invoke a STATICCALL which will use the external smart contract storage for the token smart contract
        return Token(token_address).getBalance();
    }

    function getTokenBalanceDelegate(address token_address) public returns (uint256){
        bytes memory payload = abi.encodeWithSignature("getBalance()");
        (bool success, bytes memory result) =  address(token_address).delegatecall(payload);
        return abi.decode(result, (uint256));
    }


    constructor() public {

    }

    // do not allow deposits
    function() external{
        revert();
    }
}