pragma solidity ^0.4.23;


contract HeliosDelegatedToken {

    function getStorageAddress()
        public
        returns (address)
    {
        return address(this);
    }

    function getSender()
        public
        returns (address)
    {
        return address(msg.sender);
    }

    function getOrigin()
        public
        returns (address)
    {
        return address(tx.origin);
    }

    function getCoinbase()
        public
        returns (address)
    {
        return address(block.coinbase);
    }

}