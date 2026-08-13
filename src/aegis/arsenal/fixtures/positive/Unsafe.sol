pragma solidity ^0.8.0;
contract Unsafe {
    mapping(address => uint) public balances;
    function withdraw() public {
        (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
