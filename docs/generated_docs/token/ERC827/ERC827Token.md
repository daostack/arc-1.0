# ERC827Token
[see the source](https://github.com/daostack/arc/tree/master/contracts/token/ERC827/ERC827Token.sol)
> ERC827, an extension of ERC20 token standard


**Execution cost**: less than 568 gas

**Deployment cost**: less than 537400 gas

**Combined cost**: less than 537968 gas


## Events
### Approval(address,address,uint256)


**Execution cost**: No bound available


Params:

1. **owner** *of type `address`*
2. **spender** *of type `address`*
3. **value** *of type `uint256`*

--- 
### Transfer(address,address,uint256)


**Execution cost**: No bound available


Params:

1. **from** *of type `address`*
2. **to** *of type `address`*
3. **value** *of type `uint256`*


## Methods
### increaseApprovalAndCall(address,uint256,bytes)
>
> Addition to StandardToken methods. Increase the amount of tokens that an owner allowed to a spender and execute a call with the sent data. approve should be called when allowed[_spender] == 0. To increment allowed value is better to use this function to avoid 2 calls (and wait until the first transaction is mined) From MonolithDAO Token.sol


**Execution cost**: No bound available

**Attributes**: payable


Params:

1. **_spender** *of type `address`*

    > The address which will spend the funds.

2. **_addedValue** *of type `uint256`*

    > The amount of tokens to increase the allowance by.

3. **_data** *of type `bytes`*

    > ABI-encoded contract call to call `_spender` address.


Returns:


1. **output_0** *of type `bool`*

--- 
### allowance(address,address)
>
> Function to check the amount of tokens that an owner allowed to a spender.


**Execution cost**: less than 972 gas

**Attributes**: constant


Params:

1. **_owner** *of type `address`*

    > address The address which owns the funds.

2. **_spender** *of type `address`*

    > address The address which will spend the funds.


Returns:

> A uint256 specifying the amount of tokens still available for the spender.

1. **output_0** *of type `uint256`*

--- 
### transfer(address,uint256)
>
> Transfer token for a specified address


**Execution cost**: No bound available


Params:

1. **_to** *of type `address`*

    > The address to transfer to.

2. **_value** *of type `uint256`*

    > The amount to be transferred.


Returns:


1. **output_0** *of type `bool`*

--- 
### approve(address,uint256)
>
> Approve the passed address to spend the specified amount of tokens on behalf of msg.sender. Beware that changing an allowance with this method brings the risk that someone may use both the old and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards: https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729


**Execution cost**: less than 22332 gas


Params:

1. **_spender** *of type `address`*

    > The address which will spend the funds.

2. **_value** *of type `uint256`*

    > The amount of tokens to be spent.


Returns:


1. **output_0** *of type `bool`*

--- 
### approveAndCall(address,uint256,bytes)
>
> Addition to ERC20 token methods. It allows to approve the transfer of value and execute a call with the sent data. Beware that changing an allowance with this method brings the risk that someone may use both the old and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards: https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729


**Execution cost**: No bound available

**Attributes**: payable


Params:

1. **_spender** *of type `address`*

    > The address that will spend the funds.

2. **_value** *of type `uint256`*

    > The amount of tokens to be spent.

3. **_data** *of type `bytes`*

    > ABI-encoded contract call to call `_spender` address.


Returns:

> true if the call function was executed successfully

1. **output_0** *of type `bool`*

--- 
### balanceOf(address)
>
> Gets the balance of the specified address.


**Execution cost**: less than 719 gas

**Attributes**: constant


Params:

1. **_owner** *of type `address`*

    > The address to query the the balance of.


Returns:

> An uint256 representing the amount owned by the passed address.

1. **output_0** *of type `uint256`*

--- 
### decreaseApproval(address,uint256)
>
> Decrease the amount of tokens that an owner allowed to a spender. approve should be called when allowed[_spender] == 0. To decrement allowed value is better to use this function to avoid 2 calls (and wait until the first transaction is mined) From MonolithDAO Token.sol


**Execution cost**: No bound available


Params:

1. **_spender** *of type `address`*

    > The address which will spend the funds.

2. **_subtractedValue** *of type `uint256`*

    > The amount of tokens to decrease the allowance by.


Returns:


1. **output_0** *of type `bool`*

--- 
### decreaseApprovalAndCall(address,uint256,bytes)
>
> Addition to StandardToken methods. Decrease the amount of tokens that an owner allowed to a spender and execute a call with the sent data. approve should be called when allowed[_spender] == 0. To decrement allowed value is better to use this function to avoid 2 calls (and wait until the first transaction is mined) From MonolithDAO Token.sol


**Execution cost**: No bound available

**Attributes**: payable


Params:

1. **_spender** *of type `address`*

    > The address which will spend the funds.

2. **_subtractedValue** *of type `uint256`*

    > The amount of tokens to decrease the allowance by.

3. **_data** *of type `bytes`*

    > ABI-encoded contract call to call `_spender` address.


Returns:


1. **output_0** *of type `bool`*

--- 
### increaseApproval(address,uint256)
>
> Increase the amount of tokens that an owner allowed to a spender. approve should be called when allowed[_spender] == 0. To increment allowed value is better to use this function to avoid 2 calls (and wait until the first transaction is mined) From MonolithDAO Token.sol


**Execution cost**: No bound available


Params:

1. **_spender** *of type `address`*

    > The address which will spend the funds.

2. **_addedValue** *of type `uint256`*

    > The amount of tokens to increase the allowance by.


Returns:


1. **output_0** *of type `bool`*

--- 
### totalSupply()
>
> Total number of tokens in existence


**Execution cost**: less than 406 gas

**Attributes**: constant



Returns:


1. **output_0** *of type `uint256`*

--- 
### transferAndCall(address,uint256,bytes)
>
> Addition to ERC20 token methods. Transfer tokens to a specified address and execute a call with the sent data on the same transaction


**Execution cost**: No bound available

**Attributes**: payable


Params:

1. **_to** *of type `address`*

    > address The address which you want to transfer to

2. **_value** *of type `uint256`*

    > uint256 the amout of tokens to be transfered

3. **_data** *of type `bytes`*

    > ABI-encoded contract call to call `_to` address.


Returns:

> true if the call function was executed successfully

1. **output_0** *of type `bool`*

--- 
### transferFrom(address,address,uint256)
>
> Transfer tokens from one address to another


**Execution cost**: No bound available


Params:

1. **_from** *of type `address`*

    > address The address which you want to send tokens from

2. **_to** *of type `address`*

    > address The address which you want to transfer to

3. **_value** *of type `uint256`*

    > uint256 the amount of tokens to be transferred


Returns:


1. **output_0** *of type `bool`*

--- 
### transferFromAndCall(address,address,uint256,bytes)
>
> Addition to ERC20 token methods. Transfer tokens from one address to another and make a contract call on the same transaction


**Execution cost**: No bound available

**Attributes**: payable


Params:

1. **_from** *of type `address`*

    > The address which you want to send tokens from

2. **_to** *of type `address`*

    > The address which you want to transfer to

3. **_value** *of type `uint256`*

    > The amout of tokens to be transferred

4. **_data** *of type `bytes`*

    > ABI-encoded contract call to call `_to` address.


Returns:

> true if the call function was executed successfully

1. **output_0** *of type `bool`*

[Back to the top ↑](#erc827token)
