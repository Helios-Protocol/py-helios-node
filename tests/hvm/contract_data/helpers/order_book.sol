pragma solidity ^100.5.11;

import "safe_math.sol";

// This uses a linkedlist to maintain a sorted order book for every token contract address
contract OrderBook {
    using SafeMath for uint256;

    // price is in wei. it is the amount of buy_token you would buy for 1 ether (10**18) of sell_token.
    struct Order{
        bytes32 next;
        uint256 amount_remaining;
        uint256 price;
        address user;
    }

    // The token contract addresses used as keys are the base of every pair.
    // Buy and sell order books have reversed sell_token and buy_token keys
    mapping (address => mapping (address => bytes32)) public head; // the head of trade sell_token to trade buy_token
    mapping (address => mapping (address => uint256)) public nonce; // the nonce of trade sell_token to trade buy_token

    // These are always ordered highest price to lowest
    mapping (address => mapping (address => mapping(bytes32 => Order))) public orders; //mapping of sell_token token_contract_address => buy_token token_contract_address => elements of linked list for order book

    function OrderBook(){}

    function addOrder(address sell_token, address buy_token, uint256 amount, uint256 price) public {
        (previous_id, next_id) = bisectGetIds(sell_token, buy_token, price);
        Order memory new_order = Order(next_id,amount,price,msg.sender);

        bytes32 id = keccak256(new_order.amount,new_order.price,new_order.user,nonce[sell_token][buy_token]);
        orders[sell_token][buy_token][id] = new_order;
        nonce[sell_token][buy_token] = nonce[sell_token][buy_token].add(1);

        if(previous_id == bytes32(0)){
            // if the previous_id is 0, then this is the new head.
            head[sell_token][buy_token] = id;
        }else{
            // otherwise, we need to change the next parameter on the previous order
            orders[sell_token][buy_token][previous_id].next = id;
        }
    }

    function bisectGetIds(address sell_token, address buy_token, uint256 price){
        // gets the id if the order above and below this one
        bytes32 memory previous_id;
        bytes32 memory current_id = heads[sell_token][buy_token];
        if(current_id == bytes32(0)){
            return(previous_id, current_id);
        }else{

            while(current_id != bytes32(0)){
                // if the new price is higher, then it is less than the previous_id, but greater than current_id
                if(price > orders[sell_token][buy_token][current_id].price){
                    return(previous_id, current_id);
                }
                previous_id = current_id;
                current_id = orders[sell_token][buy_token][current_id].next;
            }
            // if we get to the end, then this price is less than all of them. current_id will = bytes32(0), and previous_id will = tail of chain
            return(previous_id, current_id);
        }
    }

    //add delete function. but it can only delete from the head side.


}