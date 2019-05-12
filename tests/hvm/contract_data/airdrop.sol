pragma solidity ^0.4.23;

/**
 * Generic airdrop smart contract thats ownable
 *
 */

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;
  address public newOwnerTemp;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  constructor() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    newOwnerTemp = newOwner;
  }

  function acceptOwnership() public {
        require(msg.sender == newOwnerTemp);
        emit OwnershipTransferred(owner, newOwnerTemp);
        owner = newOwnerTemp;
        newOwnerTemp = address(0x0);
    }

}

contract ERC20 {
  function transfer(address _recipient, uint256 _value) public returns (bool success);
}

contract Airdrop is Ownable {
  function drop(ERC20 token, address[] recipients, uint256[] values) public onlyOwner {
    for (uint256 i = 0; i < recipients.length; i++) {
      token.transfer(recipients[i], values[i]);
    }
  }
}