pragma solidity ^100.5.11;

import "./safe_math.sol";

// This uses a linkedlist to maintain a sorted order book for every token contract address
contract OrderBook {
    using SafeMath for uint256;

    // price is in wei. it is the ratio amount_buy/amount_sell * 1 ether
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

    // These are always ordered lowest price to highest price
    mapping (address => mapping (address => mapping(bytes32 => Order))) public orders; //mapping of sell_token token_contract_address => buy_token token_contract_address => elements of linked list for order book

    mapping (address => mapping (address => uint256)) public amount_in_orders; // Variable to hold the amount someone has on order. user wallet address => token address => amount

    constructor() public {}

    function addOrder(address sell_token, address buy_token, uint256 amount, uint256 price) internal {
        (bytes32 previous_id, bytes32 next_id) = bisectGetIds(sell_token, buy_token, price);
        Order memory new_order = Order(next_id,amount,price,msg.sender);

        bytes32 id = keccak256(abi.encodePacked(new_order.amount_remaining,new_order.price,new_order.user,nonce[sell_token][buy_token]));
        orders[sell_token][buy_token][id] = new_order;
        nonce[sell_token][buy_token] = nonce[sell_token][buy_token].add(1);

        if(previous_id == bytes32(0)){
            // if the previous_id is 0, then this is the new head.
            head[sell_token][buy_token] = id;
        }else{
            // otherwise, we need to change the next parameter on the previous order
            orders[sell_token][buy_token][previous_id].next = id;
        }
        amount_in_orders[msg.sender][sell_token] = amount_in_orders[msg.sender][sell_token].add(amount);
    }

    function bisectGetIds(address sell_token, address buy_token, uint256 price) internal returns(bytes32, bytes32){
        // gets the id if the order above and below this one
        bytes32 previous_id;
        bytes32 current_id = head[sell_token][buy_token];
        if(current_id == bytes32(0)){
            return(previous_id, current_id);
        }else{

            while(current_id != bytes32(0)){
                // if the new price is higher, then it is less than the previous_id, but greater than current_id
                if(price < orders[sell_token][buy_token][current_id].price){
                    return(previous_id, current_id);
                }
                previous_id = current_id;
                current_id = orders[sell_token][buy_token][current_id].next;
            }
            // if we get to the end, then this price is less than all of them. current_id will = bytes32(0), and previous_id will = tail of chain
            return(previous_id, current_id);
        }
    }

    function deleteOrder(address sell_token, address buy_token, bytes32 order_id) internal {
        bytes32 current_id = head[sell_token][buy_token];
        if(orders[sell_token][buy_token][order_id].user != address(0)){
            if(order_id == head[sell_token][buy_token]){
                // if this was the head, just delete the order and set the new head
                head[sell_token][buy_token] = orders[sell_token][buy_token][order_id].next;
                amount_in_orders[orders[sell_token][buy_token][order_id].user][sell_token] = amount_in_orders[orders[sell_token][buy_token][order_id].user][sell_token].sub(orders[sell_token][buy_token][order_id].amount_remaining);
                delete orders[sell_token][buy_token][order_id];
            }else{
                // otherwise, go looking for it
                while(current_id != bytes32(0)){
                    if(orders[sell_token][buy_token][current_id].next == order_id){
                        // if the next id is the one we want to delete, set next to the one after that, and then delete it.
                        orders[sell_token][buy_token][current_id].next = orders[sell_token][buy_token][order_id].next;
                        amount_in_orders[orders[sell_token][buy_token][order_id].user][sell_token] = amount_in_orders[orders[sell_token][buy_token][order_id].user][sell_token].sub(orders[sell_token][buy_token][order_id].amount_remaining);
                        delete orders[sell_token][buy_token][order_id];

                        return;
                    }
                    current_id = orders[sell_token][buy_token][current_id].next;
                }
            }

        }
    }

    function subtractAmountFromOrder(address sell_token, address buy_token, bytes32 order_id, uint256 amount) internal{
        require(
            head[sell_token][buy_token] == order_id,
            "Can only buy from the top of the order book."
        );
        require(
            amount <= orders[sell_token][buy_token][order_id].amount_remaining,
            "Cannot subtract more than the amount remaining in the order."
        );

        if(amount == orders[sell_token][buy_token][order_id].amount_remaining){

            deleteOrder(sell_token, buy_token, order_id);
        }else{
//            log0(bytes32('ZZZZZZZZZZZZ'));
//            log0(bytes32(amount));
            orders[sell_token][buy_token][order_id].amount_remaining = orders[sell_token][buy_token][order_id].amount_remaining.sub(amount);
            amount_in_orders[orders[sell_token][buy_token][order_id].user][sell_token] = amount_in_orders[orders[sell_token][buy_token][order_id].user][sell_token].sub(amount);
        }
    }

    function getOrderBookWeb3(address sell_token, address buy_token) public returns (uint256[2][100] memory){
        uint256[2][100] memory array_to_return;
        bytes32 current_id = head[sell_token][buy_token];
        uint i = 0;
        while(current_id != bytes32(0)){
            //array_to_return[].push([orders[sell_token][buy_token][current_id].price, orders[sell_token][buy_token][current_id].amount_remaining]);
            array_to_return[i] = [orders[sell_token][buy_token][current_id].amount_remaining, orders[sell_token][buy_token][current_id].price];

            current_id = orders[sell_token][buy_token][current_id].next;
            i += 1;
        }
        return array_to_return;
    }

    function getAmountInOrders(address user, address token) public returns (uint256){
        return amount_in_orders[user][token];
    }



}