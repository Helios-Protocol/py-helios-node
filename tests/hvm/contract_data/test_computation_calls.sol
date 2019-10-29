pragma solidity ^0.5.11;

contract Test {

//    function drop(address payable token_contract_address, address payable _to, uint256 amount) public payable {
//
//        bytes4 sig = bytes4(keccak256("send(uint256)")); //Function signature
//
//        assembly {
//            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
//            mstore(x,sig) //Place signature at beginning of empty storage
//            mstore(add(x,0x04),amount) //Place first argument directly next to signature
//
//            let success := surrogatecall(100000, //100k gas
//                                        token_contract_address, //Delegated token contract address
//                                        0,       //Value
//                                        1,      //Execute on send?
//                                        _to,   //To addr
//                                        x,    //Inputs are stored at location x
//                                        0x24 //Inputs are 36 bytes long
//                                        )
//
//        }
//    }

    function test_surrogatecall(address token_contract_address, address call_to, bool call_execute_on_send, uint256 call_value, uint256 call_gas) public payable {

        bytes4 sig = bytes4(keccak256("dummy(uint256)")); //Function signature
        uint256 amount = 10;

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,sig) //Place signature at beginning of empty storage
            mstore(add(x,0x04),amount) //Place first argument directly next to signature

            let success := surrogatecall(call_gas, //100k gas
                                        token_contract_address, //Delegated token contract address
                                        call_value,       //Value
                                        1,      //Execute on send?
                                        call_to,   //To addr
                                        x,    //Inputs are stored at location x
                                        0x24 //Inputs are 32 bytes long
                                        )

        }
    }

    function test_call(address token_contract_address, uint256 call_value, uint256 call_gas) public payable{

        bytes4 sig = bytes4(keccak256("dummy(uint256)")); //Function signature

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,sig) //Place signature at beginning of empty storage

            let success := call(call_gas, //100k gas
                                token_contract_address, //Delegated token contract address
                                call_value,       //Value
                                x,    //Inputs are stored at location x
                                0x04, //Inputs are 4 bytes long,
                                x, //Store output over input (saves space)
                                0x20 //Outputs are 32 bytes long
                                )

        }
    }

    function test_send(address payable call_to, uint256 call_value) public payable{
        call_to.send(call_value);


    }
    function test_transfer(address payable call_to, uint256 call_value) public payable{
        call_to.transfer(call_value);


    }

    //also check to make sure they return the address
    function test_create(uint256 call_value, uint256 call_gas) public payable returns (address){

        bytes4 data = bytes4(keccak256("random data")); //Function signature
        address contract_address;

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,data) //Place signature at beginning of empty storage

            let contract_address := create(call_value,
                                x,    //Inputs are stored at location x
                                0x24 //Inputs are 36 bytes long,
                                )

        }
        return contract_address;
    }

    function test_create2(uint256 call_value, uint256 call_gas) public payable returns (address){

        bytes4 data = bytes4(keccak256("random data")); //Function signature
        bytes32 salt = bytes4(keccak256("random salt")); //Function signature
        address contract_address;

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,data) //Place signature at beginning of empty storage

            let contract_address := create2(call_value,
                                        x,    //Inputs are stored at location x
                                        0x24, //Inputs are 36 bytes long,
                                        salt
                                        )


        }
        return contract_address;
    }

    function() external payable { }
}