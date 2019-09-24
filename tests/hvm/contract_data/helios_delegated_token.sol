pragma solidity ^0.4.23;

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



contract HeliosDelegatedToken {
    using SafeMath for uint256;
    uint256 balance;
    event Mint(address indexed _address, uint256 value);
    event IsSend(address indexed origin, address indexed _this, bool value);

    function is_send() internal view returns (bool){
        return address(tx.origin) == address(this);
    }

    function mintSender(uint256 amount) public {
        if(is_send()){
            emit IsSend(tx.origin, address(this), true);
            balance = balance.add(amount);
        }else{
            emit IsSend(tx.origin, address(this), false);
        }
    }

    function getBalance() public view returns (uint256) {
        return balance;
    }

    function send(address _to, uint256 amount) public {
        if(is_send()){
            emit IsSend(tx.origin, address(this), true);
            require(amount <= balance);
            balance = balance.sub(amount);
        }else{
            emit IsSend(tx.origin, address(this), false);
            // Here need to check to make sure tx.is_send == true
            balance = balance.add(amount);
        }
    }


//    function getStorageAddress()
//        public
//        returns (address)
//    {
//        return address(this);
//    }
//
//    function getSender()
//        public
//        returns (address)
//    {
//        return address(msg.sender);
//    }
//
//    function getOrigin()
//        public
//        returns (address)
//    {
//        return address(tx.origin);
//    }
//
//    function getCoinbase()
//        public
//        returns (address)
//    {
//        return address(block.coinbase);
//    }


}