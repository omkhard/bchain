# ============================================================
#  demo_contracts.py  —  Example Solidity contracts
# ============================================================
#
#  These are stored as Python multi-line strings (triple quotes).
#  They are imported by app.py and served to the browser
#  when the user clicks "Load Vulnerable" or "Load Safe".
#
# ============================================================

VULNERABLE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ⚠️  VULNERABLE CONTRACT — FOR EDUCATIONAL USE ONLY
// This contract demonstrates multiple reentrancy vulnerabilities.
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // ❌ Classic reentrancy: external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // DANGER: .call happens BEFORE balance is updated
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // ❌ Too late — attacker has already re-entered above
        balances[msg.sender] -= amount;
    }

    // ❌ Another vulnerable function
    function withdrawAll() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Nothing to withdraw");

        // ❌ Raw call, no guard, state update after
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    // ❌ External call inside a loop — very dangerous
    function distributeRewards(address[] calldata users, uint256 reward) external {
        for (uint i = 0; i < users.length; i++) {
            (bool ok, ) = users[i].call{value: reward}("");
        }
    }

    // ❌ Complex receive() — risky
    receive() external payable {
        if (msg.value > 0) {
            balances[msg.sender] += msg.value;
            _processDeposit(msg.sender);
        }
    }

    function _processDeposit(address user) internal {
        balances[user] += 1;
    }
}'''


SAFE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// ✅ SAFE CONTRACT — Demonstrates best practices
contract SecureBank is ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // ✅ CEI pattern + nonReentrant guard
    function withdraw(uint256 amount) external nonReentrant {
        // ✅ CHECK — validate inputs
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ✅ EFFECT — update state BEFORE any external call
        balances[msg.sender] -= amount;

        // ✅ INTERACT — external call is LAST
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    // ✅ Also protected with nonReentrant
    function withdrawAll() external nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Nothing to withdraw");

        // ✅ Effect first
        balances[msg.sender] = 0;

        // ✅ Then interact
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "Transfer failed");

        emit Withdrawal(msg.sender, bal);
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }

    // ✅ Minimal receive — no complex logic
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}'''
