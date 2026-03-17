import json
from pathlib import Path
from slither.slither import Slither
from web3 import Web3

class SmartContractScanner:
    def __init__(self, contract_path):
        self.contract_path = contract_path
        self.vulnerabilities = []
        self.slither = None
    
    def scan(self):
        """Main scanning function"""
        try:
            self.slither = Slither(self.contract_path)
            self._detect_vulnerabilities()
            return self.generate_report()
        except Exception as e:
            return {"error": str(e)}
    
    def _detect_vulnerabilities(self):
        """Detect various vulnerability types"""
        for contract in self.slither.contracts:
            self._check_reentrancy(contract)
            self._check_integer_overflow(contract)
            self._check_unchecked_calls(contract)
            self._check_access_control(contract)
    
    def _check_reentrancy(self, contract):
        """Detect reentrancy vulnerabilities"""
        for function in contract.functions:
            external_calls = [c for c in function.external_calls]
            state_updates = [s for s in function.state_variables_written]
            
            # If external call happens before state update
            if external_calls and state_updates:
                self.vulnerabilities.append({
                    "type": "Reentrancy",
                    "severity": "Critical",
                    "contract": contract.name,
                    "function": function.name,
                    "line": function.source_mapping.get("lines", [])
                })
    
    def _check_integer_overflow(self, contract):
        """Detect integer overflow/underflow"""
        for function in contract.functions:
            for node in function.nodes:
                if "+" in str(node) or "-" in str(node):
                    self.vulnerabilities.append({
                        "type": "Integer Overflow/Underflow",
                        "severity": "High",
                        "contract": contract.name,
                        "function": function.name
                    })
    
    def _check_unchecked_calls(self, contract):
        """Detect unchecked external calls"""
        for function in contract.functions:
            for call in function.external_calls:
                if not self._is_call_checked(call):
                    self.vulnerabilities.append({
                        "type": "Unchecked Call",
                        "severity": "Medium",
                        "contract": contract.name,
                        "function": function.name
                    })
    
    def _check_access_control(self, contract):
        """Detect missing access control"""
        for function in contract.functions:
            if function.visibility == "public" and not self._has_access_control(function):
                self.vulnerabilities.append({
                    "type": "Missing Access Control",
                    "severity": "High",
                    "contract": contract.name,
                    "function": function.name
                })
    
    def _is_call_checked(self, call):
        """Check if external call result is validated"""
        return True  # Placeholder logic
    
    def _has_access_control(self, function):
        """Check if function has access control modifiers"""
        return len(function.modifiers) > 0
    
    def generate_report(self):
        """Generate vulnerability report"""
        return {
            "contract": self.contract_path,
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "severity_breakdown": self._severity_breakdown()
        }
    
    def _severity_breakdown(self):
        """
