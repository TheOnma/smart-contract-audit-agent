/**
 * Certora rule: multicall cannot grant authorization that the victim didn't set explicitly.
 *
 * This closes the composability gap — the existing Certora suite treats multicall as
 * HAVOC_ALL, so no authorization property is verified across multicall batches.
 *
 * If this rule FAILS: a multicall sequence can grant unexpected permissions —
 * potential Medium authorization bypass finding.
 *
 * TODO: Update contract name and setIsAuthorized / isAuthorized signatures.
 */

methods {
    // [TODO] Map multicall and authorization functions
    // function multicall(bytes[] calldata calls) external;
    // function setIsAuthorized(address authorized, bool value, address onBehalf) external;
    // function isAuthorized(address onBehalf, address authorized) external returns (bool) envfree;
}

/**
 * A victim's authorization state cannot change across a multicall
 * unless the victim (or someone they already authorized) is msg.sender.
 *
 * The intuition: if victim didn't call into the protocol in this transaction,
 * their authorization state must not change.
 */
rule multicallNoAuthEscalation(env e) {
    address victim;
    address attacker;

    // Attacker is not the victim and is not pre-authorized
    require e.msg.sender != victim;
    // require !isAuthorized(victim, e.msg.sender);  // [TODO] uncomment

    // Capture pre-state
    // bool preAuth = isAuthorized(victim, attacker);  // [TODO] uncomment

    // Run an arbitrary multicall batch
    bytes[] calldataArgs;
    // multicall(e, calldataArgs);  // [TODO] uncomment

    // Post-state: victim's authorization of attacker must not have changed
    // assert isAuthorized(victim, attacker) == preAuth,  // [TODO] uncomment
    //        "multicall changed victim auth state without victim's consent";
}

/**
 * Variant: setIsAuthorized within a multicall can only modify the caller's own
 * authorization mappings, not those of third parties.
 */
rule setIsAuthorizedOnlyModifiesCallerMappings(env e) {
    address onBehalf;
    address authorized;
    bool newValue;

    require onBehalf != e.msg.sender;
    // require !isAuthorized(onBehalf, e.msg.sender);  // caller not pre-authorized

    // bool preBefore = isAuthorized(onBehalf, authorized);  // [TODO] uncomment

    // setIsAuthorized(e, authorized, newValue, onBehalf);  // [TODO] should revert

    // assert isAuthorized(onBehalf, authorized) == preBefore,  // [TODO] uncomment
    //        "setIsAuthorized modified non-caller's mapping without authorization";
}
