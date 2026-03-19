// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SecureContract
/// @notice This contract demonstrates fixes for common vulnerabilities

contract SecureContract {
    mapping(address => uint) public balances;
    address public owner;
    
    // FIX 1: ReentrancyGuard - mutex lock
    bool private locked;

    modifier noReentrant() {
        require(!locked, "Reentrant call detected");
        locked = true;
        _;
        locked = false;
    }

    // FIX 3: Access Control Modifier
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // =============================================
    // FIX 1: Reentrancy Fixed
    // Solution: CEI pattern + ReentrancyGuard
    // =============================================
    function withdraw(uint amount) external noReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // FIXED: Update state BEFORE external call (CEI Pattern)
        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // =============================================
    // FIX 2: Integer Overflow Fixed
    // Solution: Solidity 0.8.0+ has built-in overflow checks
    // =============================================
    function safeAdd(uint a, uint b) public pure returns (uint) {
        // Solidity 0.8.0+ automatically reverts on overflow
        return a + b;
    }

    // =============================================
    // FIX 3: Access Control Fixed
    // Solution: onlyOwner modifier applied
    // =============================================
    function setOwner(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Invalid address");
        owner = newOwner;
    }

    // =============================================
    // FIX 4: Checked External Call Fixed
    // Solution: Use transfer() or check return value
    // =============================================
    function safeSend(address payable recipient, uint amount) public onlyOwner {
        require(address(this).balance >= amount, "Insufficient contract balance");
        // FIXED: transfer() reverts automatically on failure
        recipient.transfer(amount);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
