# ============================================================
#  demo_contracts.py — Example contracts for the auditor
#  Each contract demonstrates a different access control failure
# ============================================================

CONTRACTS = {

# ── 1. Fully Vulnerable Contract ──────────────────────────────────────────────
"vulnerable_vault": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ⚠️  VULNERABLE VAULT — FOR EDUCATIONAL USE ONLY
// This contract has MULTIPLE access control failures.
// Real-world exploit: Parity Wallet ($30M), Uranium Finance ($50M)

contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    bool public paused;
    uint256 public fee;

    // ❌ No constructor — owner never set properly
    // ❌ No event on deployment

    // ❌ CRITICAL: Anyone can call init() and become owner
    function init(address _owner) public {
        owner = _owner;
    }

    // ❌ HIGH: No access control on withdraw
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // ❌ CRITICAL: Anyone can destroy the contract
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    // ❌ HIGH: No access control on mint
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    // ❌ HIGH: Public function modifies state with no checks
    function setFee(uint256 _fee) public {
        fee = _fee;
    }

    // ❌ HIGH: No access control on pause
    function pause() external {
        paused = true;
    }

    // ❌ MEDIUM: Uses tx.origin — phishing vulnerable
    function adminWithdraw(uint256 amount) external {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(amount);
    }

    // ❌ MEDIUM: transferOwnership — no zero-address check, no event
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    // ❌ MEDIUM: Hardcoded address authorization
    function emergencyWithdraw() external {
        require(msg.sender == 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B);
        payable(msg.sender).transfer(address(this).balance);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}''',


# ── 2. Secure Contract ────────────────────────────────────────────────────────
"secure_vault": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ✅ SECURE VAULT — Demonstrates access control best practices

contract SecureVault {
    address public owner;
    address public pendingOwner;
    mapping(address => uint256) public balances;
    bool public paused;
    uint256 public fee;
    bool private initialized;

    // ✅ Events for all sensitive operations
    event OwnershipTransferred(address indexed prev, address indexed next);
    event OwnershipAccepted(address indexed newOwner);
    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event Paused(address by);
    event Unpaused(address by);
    event Withdrawn(address indexed user, uint256 amount);

    // ✅ Proper modifier with require
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier notPaused() {
        require(!paused, "Contract paused");
        _;
    }

    // ✅ Constructor — sets owner at deploy time, not later
    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ✅ Protected initialize with initialized flag
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        require(_owner != address(0), "Zero address");
        initialized = true;
        owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
    }

    // ✅ Two-step ownership transfer
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address not allowed");
        pendingOwner = newOwner;
        emit OwnershipTransferred(owner, newOwner);
    }

    // ✅ New owner must accept
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        emit OwnershipAccepted(pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    // ✅ msg.sender auth, not tx.origin
    function withdraw(uint256 amount) external notPaused {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    // ✅ selfdestruct protected
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }

    // ✅ mint protected
    function mint(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Zero address");
        balances[to] += amount;
    }

    // ✅ setFee protected + event
    function setFee(uint256 _fee) external onlyOwner {
        emit FeeUpdated(fee, _fee);
        fee = _fee;
    }

    // ✅ pause protected
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function deposit() external payable notPaused {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}''',


# ── 3. Parity Wallet Recreation ───────────────────────────────────────────────
"parity_wallet_bug": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ⚠️  PARITY WALLET BUG RECREATION — EDUCATIONAL ONLY
// In 2017, this exact pattern allowed an attacker to call
// initWallet() on the library contract and become its owner,
// then call kill() to destroy it, freezing $150M in ETH.

contract ParityWalletVulnerable {
    address public owner;
    uint256 public dailyLimit;
    mapping(address => bool) public isOwner;

    // ❌ CRITICAL: initWallet() is public with no protection
    // Anyone can call this on a deployed contract and take over
    function initWallet(address[] memory _owners, uint256 _limit) public {
        owner = _owners[0];
        dailyLimit = _limit;
        for (uint i = 0; i < _owners.length; i++) {
            isOwner[_owners[i]] = true;
        }
    }

    // ❌ CRITICAL: kill() has no guard
    // After calling initWallet(), attacker calls kill() to destroy
    function kill(address _to) public {
        selfdestruct(payable(_to));
    }

    function execute(address _to, uint256 _value) external {
        require(isOwner[msg.sender], "Not owner");
        payable(_to).transfer(_value);
    }

    receive() external payable {}
}''',


# ── 4. OpenZeppelin Role-Based Access Control Example ────────────────────────
"rbac_example": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";

// ✅ ROLE-BASED ACCESS CONTROL — Best practice for complex systems
// Uses OpenZeppelin AccessControl for granular permissions

contract TokenWithRBAC is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    mapping(address => uint256) public balances;
    bool public paused;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Paused(address account);
    event Unpaused(address account);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(BURNER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    // ✅ Only MINTER_ROLE can mint
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(to != address(0), "Zero address");
        require(!paused, "Paused");
        balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    // ✅ Only BURNER_ROLE can burn
    function burn(address from, uint256 amount) external onlyRole(BURNER_ROLE) {
        require(balances[from] >= amount, "Insufficient balance");
        balances[from] -= amount;
        emit Transfer(from, address(0), amount);
    }

    // ✅ Only PAUSER_ROLE can pause
    function pause() external onlyRole(PAUSER_ROLE) {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ✅ Admin can grant/revoke roles (inherited from AccessControl)
    // grantRole(MINTER_ROLE, address) — only DEFAULT_ADMIN_ROLE
    // revokeRole(MINTER_ROLE, address) — only DEFAULT_ADMIN_ROLE
}''',


# ── 5. tx.origin Phishing Attack Demo ────────────────────────────────────────
"tx_origin_vuln": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ⚠️  tx.origin VULNERABILITY DEMO
//
// HOW THE ATTACK WORKS:
// 1. Victim (owner) is tricked into calling Attack.exploit()
// 2. Attack.exploit() calls Wallet.transfer() on their behalf
// 3. tx.origin == owner (victim), so the check passes
// 4. Attacker drains the wallet
//
// The fix: always use msg.sender, never tx.origin

contract VulnerableWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // ❌ tx.origin auth — phishing vulnerable
    function transfer(address payable _to, uint256 _amount) public {
        require(tx.origin == owner, "Not owner");
        _to.transfer(_amount);
    }

    receive() external payable {}
}

// This is the attacker contract
// Victim is tricked into calling exploit()
contract AttackContract {
    VulnerableWallet public wallet;
    address payable public attacker;

    constructor(address _wallet) {
        wallet = VulnerableWallet(payable(_wallet));
        attacker = payable(msg.sender);
    }

    // Victim calls this (e.g., lured by a fake airdrop)
    // tx.origin = victim (owner), msg.sender = this contract
    function exploit() external {
        wallet.transfer(attacker, address(wallet).balance);
    }
}''',
}