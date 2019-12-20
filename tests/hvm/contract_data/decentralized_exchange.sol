pragma solidity ^100.5.11;

import "./helpers/smart_contract_chain.sol";
import "./helpers/safe_math.sol";
import "./helpers/execute_on_send.sol";
import "./helpers/ownable.sol";
import "./helpers/order_book.sol";


contract Token {
    function getBalance() public view returns (uint256);
    function transactionReceived(bytes32 receipt_identifier) public view returns (bool);
}

// Minting has to occur on smart contract chain because that is where the owner variable is stored.
contract DecentralizedExchange is Ownable, ExecuteOnSend, OrderBook{
    using SafeMath for uint256;

    struct PendingDepositInfo {
        uint256 amount;
        bytes32 receipt_identifier;
    }

    mapping(address => mapping (address => PendingDepositInfo[])) public pending_deposits; // wallet address -> token contract (0 for HLS) -> list of pending deposits for that contract.
    mapping(address => mapping (address => uint256)) public tokens; //mapping of token addresses to mapping of account balances (token contract = 0 means HLS)


    uint256 deposit_nonce;

    function depositTokens(address exchange_deposit_address, address token_contract_address, uint256 amount, uint256 this_deposit_nonce) public requireExecuteOnSendTx{
        if(is_send()){
            // Lets make sure they have enough balance on this chain. They could potentially spend the balance before
            // the transaction is sent, resulting in an error, but that is why we use a receipt identifier to know
            // if it was received or not.
            uint256 token_balance_on_this_chain = Token(token_contract_address).getBalance();
            require(
                amount <= token_balance_on_this_chain,
                "This chain doesn't have enough tokens for the deposit"
            );
            require(
                this_deposit_nonce == deposit_nonce,
                "Your deposit nonce is incorrect."
            );


            bytes32 receipt_identifier = getNewReceiptIdentifier(this_deposit_nonce);

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
            deposit_nonce = deposit_nonce + 1;

        }else{

            // Here lets check if it was already received, if so lets just add it to the balance
            bytes32 receipt_identifier = getNewReceiptIdentifier(this_deposit_nonce);

            bool is_transaction_received = Token(token_contract_address).transactionReceived(receipt_identifier);
            if(is_transaction_received){
                // it has already been received
                tokens[msg.sender][token_contract_address].add(amount);
            }else{
                // it has not been received
                pending_deposits[msg.sender][token_contract_address].push(
                    PendingDepositInfo({
                        amount: amount,
                        receipt_identifier: receipt_identifier
                    })
                );
            }

        }
    }

    function withdrawTokens(address token_contract_address, uint256 amount) public {
        require(token_contract_address != address(0));
        require(tokens[msg.sender][token_contract_address] >= amount);
        tokens[msg.sender][token_contract_address] = tokens[msg.sender][token_contract_address].sub(amount);

        // Send the transaction
        bytes4 sig = bytes4(keccak256("transfer(uint256)")); //Function signature
        address to = msg.sender;
        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,sig) //Place signature at beginning of empty storage (4 bytes)
            mstore(add(x,0x04),amount) //Place first argument directly next to signature (32 byte int256)

            let success := surrogatecall(100000, //100k gas
                                        token_contract_address, //Delegated token contract address
                                        0,       //Value
                                        1,      //Execute on send?
                                        to,   //To addr
                                        x,    //Inputs are stored at location x
                                        0x24 //Inputs are 4 + 32 = 36 bytes long
                                        )
        }

    }
    function getNewReceiptIdentifier(uint256 this_deposit_nonce) private returns (bytes32){
        bytes32 receipt_identifier = keccak256(abi.encodePacked(this_deposit_nonce, msg.sender));
        return receipt_identifier;
    }

    function processPendingDeposits(address wallet_address, address token_contract_address) public{
        uint i = 0;
        while(i < pending_deposits[wallet_address][token_contract_address].length){

            bool is_transaction_received = Token(token_contract_address).transactionReceived(pending_deposits[wallet_address][token_contract_address][i].receipt_identifier);
            if(is_transaction_received){
                // it has already been received
                // add to the token balance
                tokens[wallet_address][token_contract_address] = tokens[wallet_address][token_contract_address].add(pending_deposits[wallet_address][token_contract_address][i].amount);

                //delete the pending deposit element and shift the array
                if(i == pending_deposits[wallet_address][token_contract_address].length - 1){
                    // it is the last element. just delete
                    delete pending_deposits[wallet_address][token_contract_address][i];
                }else{
                    // replace the element with the one at the end of the list
                    pending_deposits[wallet_address][token_contract_address][i] = pending_deposits[wallet_address][token_contract_address][pending_deposits[wallet_address][token_contract_address].length - 1];

                    // delete the element at the end
                    delete pending_deposits[wallet_address][token_contract_address][pending_deposits[wallet_address][token_contract_address].length - 1];
                }
            }else{
                // only increment the counter if we didnt just shift the array
                i = i + 1;
            }
        }
    }

    // function to deposit HLS
    // This could fail if they don't give enough gas. Need to require a certain amount of gas
    function depositHLS() public payable {
        tokens[msg.sender][address(0)] = tokens[msg.sender][address(0)].add(msg.value);
    }

    function withdrawHLS(uint amount) public {
        require(tokens[msg.sender][address(0)] >= amount);
        tokens[msg.sender][address(0)] = tokens[msg.sender][address(0)].sub(amount);
        msg.sender.transfer(amount);
    }

    //
    // trading
    //
    function trade(address sell_token, address buy_token, uint256 amount, uint256 price){
        // to find anyone to match with, we need to check the head of the people selling buy_token, and buying sell_token
        bytes32 head = head[buy_token][sell_token];
        int256 inverse_price = 1 ether * 1 ether/price;
        while(orders[buy_token][sell_token][head].price >= inverse_price){
            if(amount < orders[buy_token][sell_token][head].amount){
                // here we do a partial order and subtract from order remaining
            }else{
                // here we take the whole order and delete it
            }
        }

    }




//    function getTokenBalance(address token_address) public view returns (uint256){
//        // This will invoke a STATICCALL which will use the external smart contract storage for the token smart contract
//        return Token(token_address).getBalance();
//    }
//
//    function getTokenBalanceDelegate(address token_address) public returns (uint256){
//        bytes memory payload = abi.encodeWithSignature("getBalance()");
//        (bool success, bytes memory result) =  address(token_address).delegatecall(payload);
//        return abi.decode(result, (uint256));
//    }


    constructor() public {

    }

    // if someone deposits HLS, call the deposit command.
    // This could fail if they don't give enough gas. Need to require a certain amount of gas
    function() external payable{
        depositHLS();
    }
}