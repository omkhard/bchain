VULNERABLE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// WARNING: VULNERABLE CONTRACT — EDUCATIONAL USE ONLY
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Classic reentrancy: external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // Too late!
    }

    function withdrawAll() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    function distributeRewards(address[] calldata users, uint256 reward) external {
        for (uint i = 0; i < users.length; i++) {
            (bool ok, ) = users[i].call{value: reward}("");
        }
    }

    receive() external payable {
        if (msg.value > 0) {
            balances[msg.sender] += msg.value;
        }
    }
}'''

SAFE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureBank is ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // CEI pattern + nonReentrant
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;          // Effect first
        (bool success, ) = msg.sender.call{value: amount}("");  // Then interact
        require(success, "Transfer failed");
        emit Withdrawal(msg.sender, amount);
    }

    function withdrawAll() external nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Nothing to withdraw");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "Transfer failed");
        emit Withdrawal(msg.sender, bal);
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}'''
