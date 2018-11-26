pragma solidity ^0.4.25;

import "./CallAccess.sol";
import "./C.sol";

/**
 * @title An Avatar holds tokens, reputation and ether for a controller
 */
contract Avatar is CallAccess, Constrained {


    string public orgName;
    address public nativeToken;
    address public nativeReputation;
    mapping (bytes32=>Call) calls;

    event ReceiveEther(address indexed _sender, uint _value);


    constructor() public {
        orgName = "Avatar";
    }

    modifier onlyThis() {
        require(msg.sender == this);
        _;
    }

    /**
    * @dev enables an avatar to receive ethers
    */
    function() public payable {
        emit ReceiveEther(msg.sender, msg.value);
    }

    /**
    * @dev the init function takes organization name, native token and reputation system
    and creates an avatar for a controller
    */
    function init(address _owner, string _orgName, DAOToken _nativeToken, Reputation _nativeReputation) external {
        require(bytes(orgName).length == 0, "Contract is already initialized");
        require(bytes(_orgName).length > 0, "Avatar organization name must not be empty");

        owner = _owner;
        orgName = _orgName;
        nativeToken = _nativeToken;
        nativeReputation = _nativeReputation;
    }

    /**
    * @dev perform a generic call to an arbitrary contract
    * @param _contract  the contract's address to call
    * @param _data ABI-encoded contract call to call `_contract` address.
    * @return the return bytes of the called contract's function.
    */
    function daoCall(address _contract, bytes _data, uint _value) public {
        require(unlockCall(_contract, _data, _value));

        // solium-disable-next-line security/no-low-level-calls
        bool result = _contract.value(eth).call(_data);
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            // Copy the returned data.
            returndatacopy(0, 0, returndatasize)

            switch result
            // call returns 0 on error.
            case 0 { revert(0, returndatasize) }
            default { return(0, returndatasize) }
        }
    }

    function grantAccess(
        address _to,
        bool _assignable,
        uint _start,
        uint _expiration,
        uint _uses,
        bool _admin,
        bool _anyContract,
        bool _anySig,
        address _contract,
        bytes4 _sig,
        bool _withValue
    ) public onlyThis {
        grantCallAccess(
            _to,
            _assignable,
            _start,
            _expiration,
            _uses,
            _admin,
            _anyContract,
            _anySig,
            _contract,
            _sig,
            _withValue);
    }

    function revokeAccess(bytes32 _keyId, address _from) public onlyThis {
        revokeCallAccess(_keyId, _from);
    }

    function addConstraint(address _constraint) public onlyThis returns(bool) {
        return super.addConstraint(_constraint);
    }

    function removeConstraint(address _constraint) public onlyThis returns(bool) {
        return super.removeConstraint(_constraint);
    }
}
