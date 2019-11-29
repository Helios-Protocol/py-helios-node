pragma solidity ^0.5.11;
import "./smart_contract_chain.sol";
import "./execute_on_send.sol";

contract TestSmartContractChain is SmartContractChain{
    event didSomething(address indexed _origin, address _this, bool value);

    function doSomething() public onlyOnSmartContractChain{
        emit didSomething(tx.origin, address(this), true);
    }

}

contract TestExecuteOnSend is ExecuteOnSend{
    event didSomething(bool value);

    function doSomething() public requireExecuteOnSendTx{
        emit didSomething(true);
    }

}