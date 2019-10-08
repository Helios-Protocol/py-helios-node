pragma solidity ^0.5.11;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
   /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    // Gas optimization: this is cheaper than asserting 'a' not being zero, but the
    // benefit is lost if 'b' is also tested.
    // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
    if (a == 0) {
      return 0;
    }
     c = a * b;
    assert(c / a == b);
    return c;
  }
   /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    // uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return a / b;
  }
   /**
  * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }
   /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
    c = a + b;
    assert(c >= a);
    return c;
  }
}

contract Test1 {
    function add(int a, int b) public pure returns(int){  //Simply add the two arguments and return
        return a+b;
    }
}

contract CompilerTest {
    using SafeMath for uint256;
    Test1 test1;

    function test_call(int a, int b) public returns (int c){
        address addr = address(test1);  //Place the test1 address on the stack
        bytes4 sig = bytes4(keccak256("add(int256,int256)")); //Function signature

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,sig) //Place signature at begining of empty storage
            mstore(add(x,0x04),a) //Place first argument directly next to signature
            mstore(add(x,0x24),b) //Place second argument next to first, padded to 32 bytes

            let success := call(5000, //5k gas
                                addr, //To addr
                                0,    //No value
                                x,    //Inputs are stored at location x
                                0x44, //Inputs are 68 bytes long
                                x,    //Store output over input (saves space)
                                0x20) //Outputs are 32 bytes long

            c := mload(x) //Assign output value to c
            mstore(0x40,add(x,0x44)) // Set storage pointer to empty space
        }
    }

//    function test_call2(int a, int b) public view returns (int c){
//        return test1.add(a,b);
//    }

    function test_call3(uint256 a, uint256 b) public pure returns (uint256 c){
        return a.add(b);
    }

    function test_call_surrogate(int a, int b) public returns (int c){
        address addr = address(test1);  //Place the test1 address on the stack
        bytes4 sig = bytes4(keccak256("add(int256,int256)")); //Function signature
        address to = address(uint160(uint(keccak256('asdfds'))));

        assembly {
            let x := mload(0x40)   //Find empty storage location using "free memory pointer"
            mstore(x,sig) //Place signature at begining of empty storage
            mstore(add(x,0x04),a) //Place first argument directly next to signature
            mstore(add(x,0x24),b) //Place second argument next to first, padded to 32 bytes

            let success := surrogatecall(5000, //5k gas
                                        addr, //To addr
                                        0,    //No value
                                        to,
                                        x,    //Inputs are stored at location x
                                        0x44 //Inputs are 68 bytes long) //Outputs are 32 bytes long
                                        )
            c := mload(x) //Assign output value to c
            mstore(0x40,add(x,0x44)) // Set storage pointer to empty space
        }
    }

}