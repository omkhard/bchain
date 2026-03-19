// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ⚠️  VULNERABLE CONTRACT — FOR EDUCATIONAL USE ONLY
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // ❌ Classic reentrancy: external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // DANGER: call happens before balance update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // ❌ Too late — attacker can re-enter before this line
        balances[msg.sender] -= amount;
    }

    // ❌ Another vulnerable function sharing state
    function withdrawAll() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Nothing to withdraw");
        
        // ❌ Raw call without guard
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    // ❌ Loop with external call
    function distributeRewards(address[] calldata users, uint256 reward) external {
        for (uint i = 0; i < users.length; i++) {
            (bool ok, ) = users[i].call{value: reward}("");
        }
    }

    receive() external payable {
        if (msg.value > 0) {
            balances[msg.sender] += msg.value;
            // complex logic in receive — risky
            _processDeposit(msg.sender);
        }
    }

    function _processDeposit(address user) internal {
        balances[user] += 1;
    }
}
