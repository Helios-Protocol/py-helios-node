pragma solidity ^0.5.11;
/**
 * @title ExecuteOnSend
 * @dev The ExecuteOnSend contract gives a function modifier that requires the transaction to
 * have execute_on_send = True. This is to ensure that the send portion of the function
 * has also been executed. ie: gaurantees that the send and receive computations occur in pairs.
 */
contract ExecuteOnSend {

    function is_send() internal view returns (bool){
        return address(tx.origin) == address(this);
    }

    modifier requireExecuteOnSendTx {
        require(
            tx.executeonsend == true,
            "This function can only be executed with transactions that have execute_on_send = true."
        );
        _;
    }

    modifier noExecuteOnSendTx {
        require(
            tx.executeonsend == false,
            "This function can only be executed with transactions that have execute_on_send = false."
        );
        _;
    }
}