// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title EnterpriseToken
 * @dev ERC20 Token with Role-Based Access Control (RBAC) for Minting and Admin tasks.
 */
contract EnterpriseToken is ERC20, ERC20Burnable, AccessControl {
    // Define role constants using keccak256 hashes
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /**
     * @param name Token Name
     * @param symbol Token Symbol
     * @param defaultAdmin The address that can grant/revoke roles
     */
    constructor(string memory name, string memory symbol, address defaultAdmin) 
        ERC20(name, symbol) 
    {
        // Set up the admin role
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(ADMIN_ROLE, defaultAdmin);
        
        // Optionally grant the admin the ability to mint initially
        _grantRole(MINTER_ROLE, defaultAdmin);
    }

    /**
     * @dev Creates `amount` new tokens for `to`.
     * Restricted to addresses with the MINTER_ROLE.
     */
    function mint(address to, uint256 amount) public {
        require(hasRole(MINTER_ROLE, msg.sender), "Caller is not a minter");
        _mint(to, amount);
    }

    /**
     * @dev Enterprise-level safety: Granting roles.
     * Only the DEFAULT_ADMIN_ROLE can call this (provided by AccessControl).
     */
    function addMinter(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(MINTER_ROLE, account);
    }

    /**
     * @dev Enterprise-level safety: Revoking roles.
     */
    function removeMinter(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(MINTER_ROLE, account);
    }
}



