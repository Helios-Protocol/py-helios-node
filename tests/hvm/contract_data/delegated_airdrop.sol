pragma solidity ^0.5.11;


contract DelegatedAirdrop {

    function drop(address token_contract_address, address _to, uint256 amount) public {

        bytes4 sig = bytes4(keccak256("send(uint256)")); //Function signature

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,sig) //Place signature at beginning of empty storage
            mstore(add(x,0x04),amount) //Place first argument directly next to signature

            let success := surrogatecall(100000, //100k gas
                                        token_contract_address, //Delegated token contract address
                                        0,       //Value
                                        1,      //Execute on send?
                                        _to,   //To addr
                                        x,    //Inputs are stored at location x
                                        0x24 //Inputs are 36 bytes long
                                        )

        }
    }

}