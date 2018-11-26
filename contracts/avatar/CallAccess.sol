pragma solidity ^0.4.25;

import "@daostack/access_control/contracts/Permissioned.sol";


contract CallAccess is Permissioned {
    event GrantCallAccess(
        bytes32 indexed _keyId,
        address indexed _to,
        bool _assignable,
        uint _start,
        uint _expiration,
        uint _uses,
        bool _admin,
        bool _anyContract,
        bool _anySig,
        bool _withValue,
        address _contract,
        bytes4 _sig
    );
    event RevokeCallAcess(address indexed _from, bytes32 indexed _keyId);
    event UnlockCallAccess(
        address indexed _caller,
        bytes32 indexed _keyId,
        address _contract,
        bytes _data,
        uint value
    );

    function grantCallAccess(
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
    )
        internal returns(bytes32)
    {
        bytes32 keyId;

        if (_admin) {
            _anyContract = false;
            _anySig = false;
            _withValue = false;
        }
        if (_admin || _anyContract) {
            _contract = address(0);
        }
        if (_admin || anySig) {
            _sig = bytes4(0);
        }

        // Hash
        keyId = callHash(_admin, _anyContract, _anySig, _withValue, _contract, _sig);
        grantKey(keyId, _id, _to, _assignable, _start, _expiration, _uses);
        emit GrantCallAccess(
            keyId,
            _to,
            _assignable,
            _start,
            _expiration,
            _uses,
            _admin,
            _anyContract,
            _anySig,
            _withValue,
            _contract,
            _sig
        );
        return lockId;
    }

    function revokeCallAccess(bytes32 _keyId, address _from) internal {
        revokeOwnerKey(_keyId, _from);
        emit UnlockCallAccess(_keyId, _from);
    }

    function unlockCall(address _contract, bytes _data, uint _value) internal returns(bool) {
        bytes4 sig = dataToSig(_data);
        bool withValue = (_value > 0);
        bytes32 keyId;

        // Try to unlock with admin:
        keyId = callHash(true, false, false, false, address(0), bytes4(0));
        if (unlock(keyId, msg.sender)) {
            emit UnlockCallAccess(msg.sender, keyId, _contract, _data, _value);
            return true;
        }
        // If calling "this" and not admin return false:
        if (_contract == this) {
            return false;
        }

        // Try to unlock with the minimum:
        keyId = callHash(false, false, false, false, _contract, sig);
        if (unlock(keyId, msg.sender) && (!withValue)) {
            emit UnlockCallAccess(msg.sender, keyId, _contract, _data, _value);
            return true;
        }
        keyId = callHash(false, false, false, true, _contract, sig);
        if (unlock(keyId, msg.sender)) {
            emit UnlockCallAccess(msg.sender, keyId, _contract, _data, _value);
            return true;
        }

        // Try to unlock with any sig:
        keyId = callHash(false, false, true, false, _contract, bytes4(0));
        if (unlock(keyId, msg.sender) && (!withValue)) {
            emit UnlockCallAccess(msg.sender, keyId, _contract, _data, _value);
            return true;
        }
        keyId = callHash(false, false, true, true, _contract, bytes4(0));
        if (unlock(keyId, msg.sender)) {
            emit UnlockCallAccess(msg.sender, keyId, _contract, _data, _value);
            return true;
        }

        // Try to unlock with any contract:
        keyId = callHash(false, true, false, false, address(0), sig);
        if (unlock(keyId, msg.sender) && (!withValue)) {
            emit UnlockCallAccess(msg.sender, keyId, _contract, _data, _value);
            return true;
        }
        keyId = callHash(false, true, false, true, address(0), sig);
        if (unlock(keyId, msg.sender)) {
            emit UnlockCallAccess(msg.sender, keyId, _contract, _data, _value);
            return true;
        }

        // Try to unlock with any contract any sig:
        keyId = callHash(false, true, true, false, address(0), bytes4(0));
        if (unlock(keyId, msg.sender) && (!withValue)) {
            emit UnlockCallAccess(msg.sender, keyId, _contract, _data, _value);
            return true;
        }
        keyId = callHash(false, true, true, true, address(0), bytes4(0));
        if (unlock(keyId, msg.sender)) {
            emit UnlockCallAccess(msg.sender, keyId, _contract, _data, _value);
            return true;
        }

        // No access:
        return false;
    }

    function dataToSig(bytes _data) private pure returns (bytes4 sig) {
        if (data.length < 4)
            return bytes4(0);
        assembly {
          sig := mload(add(_data, 4))
        }
    }

    function callHash(bool _admin, bool _anyContract, bool _anySig, bool _withValue, address _contract, bytes4 _sig) returns(bytes32) {
        keccak32(abi.encodePacked(_admin, _anyContract, _anySig, _withValue, _contract, _sig));
    }

}
