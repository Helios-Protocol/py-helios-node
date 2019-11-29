pragma solidity ^0.5.11;
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

    /**
    * @dev Allows the new owner to accept the transafer. If they don't accept, the ownership remains
    * with the previous owner.
    */
    function acceptOwnership() public {
        require(msg.sender == newOwnerTemp);
        emit OwnershipTransferred(owner, newOwnerTemp);
        owner = newOwnerTemp;
        newOwnerTemp = address(0);
    }

}