pragma solidity ^0.5.11;
/**
 * @title SmartContractChain
 * @dev The SmartContractChain contract gives functionality that allows the contract to tell if
 * it is being executed on it's own smart contract chain, or being executed on some other chain
 * using a surrogatecall, for example.
 */
contract SmartContractChain {
    bool public isSmartContractChain;
    address public smartContractAddress;

    /**
    * @dev The constructor is only executed once when the contract is deployed, on the smart contract chain.
    * So, anything done in here is specific to the smart contract chain.
    */
    constructor() public {
        isSmartContractChain = true;
        smartContractAddress = address(this);
    }

    modifier onlyOnSmartContractChain {
        require(
            isSmartContractChain == true,
            "This function can only be executed on the smart contract chain."
        );
        _;
    }

    modifier onlyFromSmartContractChain {
        require(
            msg.sender == smartContractAddress,
            "This function can only be executed when sent from the smart contract chain."
        );
        _;
    }

}