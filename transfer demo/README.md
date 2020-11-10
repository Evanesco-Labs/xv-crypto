# Demo Instructions

## Basics

This Demo command line program is to show how our confidential account scheme works.

It mainly contains two entities: account and smart contract. The account corresponds to a pair of unique public and private keys. User stores the private key independently and publish the public key in the network. Account contains two types of  assets, Public Balance and Secret Balance, both of which are kept in a certain form on the smart contract. The Public Balance is directly recorded with its actual value, which is not private and can be known on the whole network. The Secret Balance is recorded with encoded cryptographic commitment . If and only if you have the corresponding private key can you decrypt the commitment to get actual amount.

The smart contract in our scheme is simulated as a smart contract service in this Demo. For the purpose of simplifying the demonstration, the smart contract is not loaded on the blockchain. There is no functional difference between the demonstration of our scheme and the actual deployment on the blockchain, but there may be some performance differences due to the virtual machine and implementation language. 

In the Demo, we will show the main operations of the account: Deposit, Transfer, Withdraw.

- Deposit: Convert certain amount of Public Balance in the account into Secret Balance.

- Transfer: Transfer a certain amount from one account's Secret Balance to the Secret balance of another. The Secret Balance of both accounts is only visible to themselves, and the transfer amount is only visible to the two accounts.

- Withdraw: Convert certain amount Secret Balance in the account into Public Balance.

## Details

Below we show the brief process of Demo and introduce the commands and flags. You can also get instructions by entering command:

```shell
./demo -h
```

### Start Smart Contract Service 

We first start the Smart Contract Service which uses port 3040 by default. We can also set to other port with flag `port`, and other commands should also set to the same port. We keep the smart contract service alive and enter other commands in another terminal.

```shell
./demo start 
```

### Generate Account

Generating a new account needs to enter a seed string used to generate random numbers with flag `seed`.

```shell
./demo genacc -seed NiHao
```

After entering the command, in the window we should see the profile of the generated account, and let's call her Alice. The profile includes her public and private keys, the two balances, and the commitment corresponding to the Secret Balance.

```shell
PublicKey: G7JFAJ9j7UctXxasG3n6Lieebd9VL3f4GWXEQ3imUcxF
PrivateKey: At31jWtsXtmZMcXnvSjmQf5nG9fPn75J6jUCksuqLpcD
public balance: 0
secret balance: 0
commitment: KqkyW9t8xSQAnsF5k2Bt3BfULDBnu8SiJWRVPtE16oW3575dYdL3hVntuKTZsXtTmUHEd3q3RH6TdLPs89PfiBc
```

In the same way, we generate another account Bob and his profile is shown as follow:

```shell
PublicKey: 6PiUSTw64HmEunBd347JSCGeuHZgnCPsPqyj8NdeJCLq
PrivateKey: BMJn1i1x2W67ZFHFtBMuTEjJcUzjNPWytCSHeVqDwab7
public balance: 0
secret balance: 0
commitment: 4aDCvCoKyxHWZBJ7UWEKBmMNmBxrUaJKpf2gDNwxVymGu6cj5KgwJoXoR83qkdDghfVKKLSFfhb9CSTwbmbczstR
```

### Set Public Balance

For demonstration convenience, the Public Balance of the account can be set arbitrarily. Three flags has to be entered, the flag `pk`  represents the public key, flag `sk` represents the private key, and flag `amount` represents the balance amount.

``` shell
./demo setpub -pk G7JFAJ9j7UctXxasG3n6Lieebd9VL3f4GWXEQ3imUcxF -sk At31jWtsXtmZMcXnvSjmQf5nG9fPn75J6jUCksuqLpcD -amount 100
```



### Check Account

Enter the public and private keys to check Alice's account balance and commitment:

``` shell
./demo preview -pk G7JFAJ9j7UctXxasG3n6Lieebd9VL3f4GWXEQ3imUcxF -sk At31jWtsXtmZMcXnvSjmQf5nG9fPn75J6jUCksuqLpcD
```

In the window we should see the Public Balance is 100 and the Secret Balance is 0:

```shell
public balance: 100
secret balance: 0
commitment: KqkyW9t8xSQAnsF5k2Bt3BfULDBnu8SiJWRVPtE16oW3575dYdL3hVntuKTZsXtTmUHEd3q3RH6TdLPs89PfiBc
```

### Deposit

Alice deposit to convert 50 Public Balance to Secret Balance:

```shell
 ./demo deposit -pk G7JFAJ9j7UctXxasG3n6Lieebd9VL3f4GWXEQ3imUcxF -sk At31jWtsXtmZMcXnvSjmQf5nG9fPn75J6jUCksuqLpcD -amount 50
```

Check Alice's account, we should see：

```shell
public balance: 50
secret balance: 50
commitment: 36DkPkH1kuK1Wa1LLEBwpiHFonobGrcw1vJ1ceHPH9apPGgf29jbhF8YrGKQY5WexjH4R6E8JNGFisFsVY6ufvfW
```

### Transfer

In the `transfer`command, flag`from`represents sender's public key, flag`to`represents receiver's public key, flag`sk`represents sender's private key, flag`amount`represents transfer amount.

Alice confidentially transfer 50 secret balance to Bob:

```shell
./demo transfer -from G7JFAJ9j7UctXxasG3n6Lieebd9VL3f4GWXEQ3imUcxF -sk At31jWtsXtmZMcXnvSjmQf5nG9fPn75J6jUCksuqLpcD -to 6PiUSTw64HmEunBd347JSCGeuHZgnCPsPqyj8NdeJCLq -amount 50
```

Check their accounts we should see：

- Alice

```shell
public balance: 50
secret balance: 0
commitment: KqkyW9t8xSQAnsF5k2Bt3BfULDBnu8SiJWRVPtE16oW3575dYdL3hVntuKTZsXtTmUHEd3q3RH6TdLPs89PfiBc
```

- Bob

``` shell
public balance: 0
secret balance: 50
commitment: YF6bqEUWy2BTVSKXSXVSGsB991QQ3YeBJdJjhmA3kd8HQ7zu65RRfrUFoT3QivZ1warb1RHZ9TKXfVzVY6Hz3Aw
```

### Withdraw

Bob withdraw 30 from his Secret Balance to Public Balance:

```shell
./demo withdraw -pk 6PiUSTw64HmEunBd347JSCGeuHZgnCPsPqyj8NdeJCLq -sk BMJn1i1x2W67ZFHFtBMuTEjJcUzjNPWytCSHeVqDwab7 -amount 30
```

Check Bob's account we should see Public Balance increased by 30 and Secret Balance reduced by 30：

```shell
public balance: 30
secret balance: 20
commitment: 3pPa75nK2iGG1reeZRQ53NLouzcZBz8SB6YSm9nF3bQcx5tvL7mANYwtsh4vN7TqwGSe5UntWd9dM1R421QE3mqd
```

### Smart Contract Verify

Any error or abnormal operation cannot pass verification of the smart contract. For example, if Alice transfers 10 confidentially to Bob at this time, it will not be able to pass due to insufficient Secret Balance.

In the smart contract window, we should see:

```shell
exicute tx error: transfer proof verify failed
```

