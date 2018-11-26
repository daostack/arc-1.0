pragma solidity ^0.4.25;

import "../constraints/ConstraintInterface.sol";


contract Constrained {
    struct ConstraintData {
        bool isRegistered;
        ConstraintInterface.CallPhase when;
        uint idx;
    }

    mapping(address => ConstraintData) registeredConstraints;
    address[] constraints;
    uint removedConstraintsCount;

    function isConstraintRegistered(address _constraint) public view returns(bool) {
        return registeredConstraints[_constraint].isRegistered;
    }

    /**
     * @dev add or update constraint
     * @param _constraint the address of the constraint to be added.
     * @return bool which represents a success
     */
    function addConstraint(address _constraint) internal returns(bool) {
        require(!registeredConstraints[_constraint].isRegistered, "Constraint already registered");

        ConstraintInterface.CallPhase when = ConstraintInterface(_constraint).when();

        registeredConstraints[_constraint] = ConstraintData(true, when, constraints.length);

        constraints.push(_constraint);

        emit AddConstraint(_constraint, when);

        return true;
    }

    /**
     * @dev remove constraint
     * @param _constraint the address of the constraint to be remove.
     * @return bool which represents a success
     */
    function removeConstraint(address _constraint) internal returns(bool)
    {
        ConstraintInterface.CallPhase when = ConstraintInterface(_constraint).when();

        require(registeredConstraints[_constraint].isRegistered, "Constraint is not registered");

        constraints[registeredConstraints[_constraint].idx] = address(0);

        emit RemoveConstraint(_constraint, registeredConstraints[_constraint].idx, when == ConstraintInterface.CallPhase.Pre);

        delete registeredConstraints[_constraint];

        removedConstraintsCount++;

        return true;
    }

}
