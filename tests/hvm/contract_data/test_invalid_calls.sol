pragma solidity ^100.5.14;

import "./helpers/safe_math.sol";

contract OtherContract {
    function getBalance() public view returns (uint256);
}

// Minting has to occur on smart contract chain because that is where the owner variable is stored.
contract TestInvalidCalls{
    using SafeMath for uint256;


    function testCall(address contract_address) public payable{
        uint256 test = OtherContract(contract_address).getBalance();
    }

    function() external payable{
    }
}