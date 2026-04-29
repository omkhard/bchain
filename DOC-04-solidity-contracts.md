# Tool 4 — Solidity Contracts
## `VulnerableContract.sol` and `SecureContract.sol`

> **Type:** Solidity smart contracts (educational)  
> **Status:** ✅ Valid Solidity 0.8.0 — compile with `solc` or Hardhat  
> **Location:** `BCLearning/VulnerableContract.sol` · `BCLearning/SecureContract.sol`

---

## Overview

Two paired Solidity contracts that together demonstrate the most common smart contract vulnerabilities and their fixes. They are the **test subjects** used by Tools 1, 2, and 3 — every scanner demo uses these files.

---

## `VulnerableContract.sol` — The Attack Target

**Contract name:** `VulnerableBank`  
**Pragma:** `^0.8.0`  
**Purpose:** Demonstrates 4 distinct vulnerability classes in one contract

### Vulnerability 1 — Classic CEI Violation (Line 17)

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    // ❌ DANGER: External call BEFORE state update
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    // ❌ Too late — attacker has re-entered before this line
    balances[msg.sender] -= amount;
}
```

**Attack vector:** Attacker deploys a contract with a malicious `receive()` that calls `withdraw()` again. Since `balances[msg.sender]` hasn't been decremented yet, the `require` passes on every recursive call. The loop continues until the contract is drained.

**Exploit flow:**
```
Attacker.attack()
  └─ VulnerableBank.withdraw(1 ETH)
       └─ msg.sender.call{value: 1 ETH}("") → triggers Attacker.receive()
            └─ VulnerableBank.withdraw(1 ETH)  ← balance still shows 1 ETH!
                 └─ msg.sender.call{value: 1 ETH}("") → triggers Attacker.receive()
                      └─ ... repeats until contract balance = 0
```

---

### Vulnerability 2 — Second CEI Violation (Line 24)

```solidity
function withdrawAll() external {
    uint256 bal = balances[msg.sender];
    require(bal > 0, "Nothing to withdraw");
    
    // ❌ Raw call — no guard, state update comes AFTER
    (bool ok, ) = msg.sender.call{value: bal}("");
    require(ok);
    balances[msg.sender] = 0;   // ❌ Too late
}
```

Same class of vulnerability as Withdraw, second entry point for the attack.

---

### Vulnerability 3 — External Call Inside Loop (Line 35)

```solidity
function distributeRewards(address[] calldata users, uint256 reward) external {
    for (uint i = 0; i < users.length; i++) {
        // ❌ External call inside loop — each iteration can re-enter
        (bool ok, ) = users[i].call{value: reward}("");
    }
}
```

**Two problems:**
1. Any single `users[i]` can be a malicious contract that re-enters
2. If any call fails, the entire loop reverts — funds may get stuck

---

### Vulnerability 4 — Complex receive() (Line 42)

```solidity
receive() external payable {
    if (msg.value > 0) {
        balances[msg.sender] += msg.value;
        // ❌ Complex logic in receive — exploitable in reentrancy chains
        _processDeposit(msg.sender);
    }
}
```

`receive()` should be minimal. Complex logic here can be exploited mid-attack.

---

### Scanner Results — VulnerableContract.sol

```
Pattern                              Severity   Line
─────────────────────────────────────────────────────
Missing nonReentrant Guard           HIGH         1
External Call Before State Update    CRITICAL    17
External Call Before State Update    CRITICAL    24
Raw .call() Without Guard            HIGH        30
External Call Inside Loop            CRITICAL    35
Complex receive() / fallback()       LOW         42

Security Score: 0 / 100
```

---

## `SecureContract.sol` — The Fixed Version

**Contract name:** `SecureContract`  
**Pragma:** `^0.8.0`  
**Purpose:** Demonstrates fixes for 4 vulnerability classes

### Fix 1 — Custom ReentrancyGuard Mutex

```solidity
bool private locked;

modifier noReentrant() {
    require(!locked, "Reentrant call detected");
    locked = true;
    _;          // Execute the function body
    locked = false;
}
```

This is a manual implementation of the mutex pattern. OpenZeppelin's `ReentrancyGuard` does the same thing but uses `uint256` (1/2) instead of `bool` (false/true) because writing a non-zero uint to a zero slot costs more gas — using 1→2→1 instead of false→true→false avoids the more expensive zero-write on the way out.

---

### Fix 2 — CEI Pattern Applied (Line 37)

```solidity
function withdraw(uint amount) external noReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    // ✅ EFFECT first — state updated before any external call
    balances[msg.sender] -= amount;
    
    // ✅ INTERACT last — external call is safe now
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

Even without the mutex, this CEI ordering is safe — if the attacker re-enters, `balances[msg.sender]` is already 0 and the `require` fails. The mutex adds a second layer of protection.

---

### Fix 3 — Solidity 0.8 Integer Overflow Protection

```solidity
function safeAdd(uint a, uint b) public pure returns (uint) {
    // Solidity 0.8.0+ automatically reverts on overflow
    return a + b;
}
```

In Solidity `<0.8.0`, integer overflow silently wraps around (e.g., `uint(255) + 1 = 0`). Solidity `0.8.0+` added built-in checked arithmetic — overflow causes a revert. No `SafeMath` library needed.

---

### Fix 4 — Access Control

```solidity
modifier onlyOwner() {
    require(msg.sender == owner, "Not authorized");
    _;
}

function setOwner(address newOwner) public onlyOwner {
    require(newOwner != address(0), "Invalid address");
    owner = newOwner;
}
```

Owner-only functions are protected with a modifier. The zero-address check prevents accidentally locking the contract by setting owner to `0x000...`.

---

### Fix 5 — Checked External Call

```solidity
function safeSend(address payable recipient, uint amount) public onlyOwner {
    require(address(this).balance >= amount, "Insufficient contract balance");
    // transfer() auto-reverts on failure, unlike raw .call()
    recipient.transfer(amount);
}
```

**Note:** `.transfer()` is safe for this specific use case (trusted internal function, controlled by onlyOwner) but is flagged as `MEDIUM` by the scanner because it only forwards 2300 gas which may break in future EVM gas cost changes.

---

### Scanner Results — SecureContract.sol

```
Pattern                     Severity   Line   Note
──────────────────────────────────────────────────────────────────
ReentrancyGuard Present     INFO        11    ✅ Custom noReentrant
.send() / .transfer() Usage MEDIUM      70    ⚠️  Acceptable here

Security Score: 100 / 100
```

The `.transfer()` finding is a low-priority warning, not a vulnerability — it's used in an `onlyOwner` function where the recipient is trusted.

---

## How to Compile These Contracts

```bash
# Using solc directly
solc --bin --abi VulnerableContract.sol
solc --bin --abi SecureContract.sol

# Using py-solc-x (Python)
from solcx import compile_source, install_solc
install_solc("0.8.20")
compiled = compile_source(open("VulnerableContract.sol").read(),
                          output_values=["abi", "bin"])

# Using Hardhat
npx hardhat compile
```

---

## Side-by-Side Comparison

| Aspect | VulnerableBank | SecureContract |
|---|---|---|
| Reentrancy guard | ❌ None | ✅ Custom `noReentrant` mutex |
| CEI pattern | ❌ Violated in 2 functions | ✅ Applied in `withdraw()` |
| Loop external calls | ❌ `distributeRewards()` | ✅ Not present |
| Access control | ❌ None | ✅ `onlyOwner` modifier |
| Overflow protection | ✅ Pragma 0.8.0 | ✅ Pragma 0.8.0 |
| receive() complexity | ❌ Complex | ✅ Simple |
| Scanner score | 0 / 100 | 100 / 100 |

---

## Using These Contracts for Testing

Both contracts are loaded as demo data in all three scanner tools:

```python
# In demo_contracts.py
VULNERABLE = open("VulnerableContract.sol").read()
SAFE       = open("SecureContract.sol").read()
```

They are ideal for:
- Verifying scanner output (VulnerableBank should always score 0)
- Testing new vulnerability patterns you add to the scanner
- Learning the before/after of each security fix side by side
- Writing Hardhat/Foundry tests that simulate real reentrancy attacks
