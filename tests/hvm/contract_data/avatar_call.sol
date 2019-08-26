pragma solidity ^0.4.23;


contract AvatarTest {
    function testCall(address addr)
    {
        addr.delegatecall(bytes4(keccak256("test()")));
    }

}