pragma solidity ^0.5.11;

contract Test {

    function test_surrogatecall(address token_contract_address, address call_to, bool call_execute_on_send, uint256 call_value, uint256 call_gas) public {

        bytes4 sig = bytes4(keccak256("dummy(uint256)")); //Function signature

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,sig) //Place signature at beginning of empty storage

            let success := surrogatecall(call_gas, //100k gas
                                        token_contract_address, //Delegated token contract address
                                        call_value,       //Value
                                        execute_on_send,      //Execute on send?
                                        call_to,   //To addr
                                        x,    //Inputs are stored at location x
                                        0x24 //Inputs are 36 bytes long
                                        )

        }
    }

    function test_call(address token_contract_address, uint256 call_value, uint256 call_gas) public {

        bytes4 sig = bytes4(keccak256("dummy(uint256)")); //Function signature

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,sig) //Place signature at beginning of empty storage

            let success := call(call_gas, //100k gas
                                token_contract_address, //Delegated token contract address
                                call_value,       //Value
                                x,    //Inputs are stored at location x
                                0x24, //Inputs are 36 bytes long,
                                x, //Store output over input (saves space)
                                0x20 //Outputs are 32 bytes long
                                )

        }
    }

    function test_send_all_gas(address call_to, uint256 call_value) public {
        call_to.send(call_value);


    }

    function test_send(address call_to, uint256 call_value, uint256 call_gas) public {
        call_to.send.gas(call_gas)(call_value);
    }

    function test_create(uint256 call_value, uint256 call_gas) public {

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"

            let success := create(call_value,
                                x,    //Inputs are stored at location x
                                0x24, //Inputs are 36 bytes long,
                                x, //Store output over input (saves space)
                                0x20 //Outputs are 32 bytes long
                                )

        }
    }
}