
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

/*
Council1271Quorum — Modular Council Module for DAIOv1

Purpose:
- Each DAIO “council” address can be an EIP-1271 contract wallet.
- This module supports BOTH:
  (A) Stateless approvals: submit an aggregated signature bundle at DAIO.approve(...)
  (B) Stateful approvals: members approve opId on-chain; DAIO.approve uses empty signature ("") and this
      contract returns MAGIC if quorum met.

Composition:
- Members can be EOAs OR contracts that implement EIP-1271.
- This enables subcommittees/boardrooms: a member can itself be a council contract.

Signature policy:
- For EOAs, we validate personal_sign over the 32-byte opId:
    ethHash = keccak256("\x19Ethereum Signed Message:\n32" || opId)
- For contract members, we call IERC1271(member).isValidSignature(opId, memberSig)

Bundle format (stateless):
signature bytes = abi.encode(address[] members, bytes[] memberSigs)
- members[i] must be a configured member address
- memberSigs[i] is:
    - EOA: 65-byte signature over ethHash(opId)
    - Contract member: bytes passed to that contract’s isValidSignature(opId, memberSig)

Stateful (on-chain) approvals:
- members call approveOp(opId)
- DAIO.approve(opId, councilIndex, "") passes empty signature
- isValidSignature(opId,"") returns MAGIC if popcount(approvedMask[opId]) >= threshold
*/

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

library ECDSA {
    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "ECDSA: bad v");
        return ecrecover(hash, v, r, s);
    }

    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
}

abstract contract Ownable2Step {
    address private _owner;
    address private _pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        _owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) revert NotOwner();
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function pendingOwner() public view returns (address) {
        return _pendingOwner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(_owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != _pendingOwner) revert NotPendingOwner();
        address old = _owner;
        _owner = msg.sender;
        _pendingOwner = address(0);
        emit OwnershipTransferred(old, msg.sender);
    }
}

contract Council1271Quorum is Ownable2Step, IERC1271 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    // Hard cap for bitmap approvals (practical; also keeps gas bounded)
    uint256 public constant MAX_MEMBERS = 256;

    // Members & indices (index+1 to differentiate from default 0)
    address[] private _members;
    mapping(address => uint16) public memberIndexPlus1; // 1..N if member, else 0

    // Quorum threshold
    uint16 public threshold;

    // On-chain approvals (bitmap per opId)
    mapping(bytes32 => uint256) public approvedMask;

    // Optional: require on-chain approvals only (if true, bundled sigs ignored)
    bool public onchainOnly;

    // Events
    event MemberAdded(address indexed member, uint256 index);
    event MemberRemoved(address indexed member);
    event ThresholdUpdated(uint16 oldThreshold, uint16 newThreshold);
    event OnchainOnlyToggled(bool enabled);

    event ApprovedOnchain(bytes32 indexed opId, address indexed member, uint256 newMask);
    event RevokedOnchain(bytes32 indexed opId, address indexed member, uint256 newMask);
    event ClearedOnchain(bytes32 indexed opId);

    // Errors
    error InvalidThreshold();
    error NotMember(address a);
    error AlreadyMember(address a);
    error TooManyMembers();
    error BadBundle();
    error DuplicateSigner(address a);

    constructor(
        address initialOwner_,
        address[] memory members_,
        uint16 threshold_,
        bool onchainOnly_
    ) Ownable2Step(initialOwner_) {
        onchainOnly = onchainOnly_;
        _setMembers(members_, threshold_);
    }

    /* ============================
       View helpers
       ============================ */

    function members() external view returns (address[] memory) {
        return _members;
    }

    function membersLength() external view returns (uint256) {
        return _members.length;
    }

    function isMember(address a) public view returns (bool) {
        return memberIndexPlus1[a] != 0;
    }

    function approvalsCount(bytes32 opId) public view returns (uint16) {
        return uint16(_popcount(approvedMask[opId]));
    }

    /* ============================
       Owner configuration
       ============================ */

    function setOnchainOnly(bool enabled) external onlyOwner {
        onchainOnly = enabled;
        emit OnchainOnlyToggled(enabled);
    }

    function setThreshold(uint16 newThreshold) external onlyOwner {
        _validateThreshold(newThreshold, _members.length);
        uint16 old = threshold;
        threshold = newThreshold;
        emit ThresholdUpdated(old, newThreshold);
    }

    function addMember(address m) external onlyOwner {
        if (m == address(0)) revert ZeroAddress();
        if (isMember(m)) revert AlreadyMember(m);
        if (_members.length >= MAX_MEMBERS) revert TooManyMembers();

        _members.push(m);
        memberIndexPlus1[m] = uint16(_members.length); // index+1
        emit MemberAdded(m, _members.length - 1);

        // Ensure threshold still valid
        _validateThreshold(threshold, _members.length);
    }

    function removeMember(address m) external onlyOwner {
        uint16 idxp1 = memberIndexPlus1[m];
        if (idxp1 == 0) revert NotMember(m);

        uint256 idx = uint256(idxp1 - 1);
        uint256 last = _members.length - 1;

        // swap-remove
        if (idx != last) {
            address moved = _members[last];
            _members[idx] = moved;
            memberIndexPlus1[moved] = uint16(idx + 1);
        }

        _members.pop();
        memberIndexPlus1[m] = 0;

        emit MemberRemoved(m);

        // Ensure threshold still valid
        _validateThreshold(threshold, _members.length);
    }

    function replaceAllMembers(address[] calldata newMembers, uint16 newThreshold) external onlyOwner {
        _setMembers(newMembers, newThreshold);
    }

    /* ============================
       On-chain boardroom approvals
       ============================ */

    function approveOp(bytes32 opId) external {
        uint16 idxp1 = memberIndexPlus1[msg.sender];
        if (idxp1 == 0) revert NotMember(msg.sender);

        uint256 bit = 1 << (idxp1 - 1);
        uint256 mask = approvedMask[opId];
        if ((mask & bit) != 0) return; // idempotent

        uint256 newMask = mask | bit;
        approvedMask[opId] = newMask;

        emit ApprovedOnchain(opId, msg.sender, newMask);
    }

    function revokeOp(bytes32 opId) external {
        uint16 idxp1 = memberIndexPlus1[msg.sender];
        if (idxp1 == 0) revert NotMember(msg.sender);

        uint256 bit = 1 << (idxp1 - 1);
        uint256 mask = approvedMask[opId];
        if ((mask & bit) == 0) return; // idempotent

        uint256 newMask = mask & ~bit;
        approvedMask[opId] = newMask;

        emit RevokedOnchain(opId, msg.sender, newMask);
    }

    function clearOp(bytes32 opId) external onlyOwner {
        delete approvedMask[opId];
        emit ClearedOnchain(opId);
    }

    /* ============================
       EIP-1271 validation
       ============================ */

    function isValidSignature(bytes32 opId, bytes calldata signature) external view override returns (bytes4) {
        // Mode (B): stateful on-chain approvals — use empty signature
        if (signature.length == 0 || onchainOnly) {
            uint256 mask = approvedMask[opId];
            if (_popcount(mask) >= threshold) return MAGICVALUE;
            return 0xffffffff;
        }

        // Mode (A): stateless bundle approvals
        // signature = abi.encode(address[] members, bytes[] sigs)
        (address[] memory signers, bytes[] memory sigs) = abi.decode(signature, (address[], bytes[]));
        if (signers.length != sigs.length) revert BadBundle();

        uint16 valid;
        uint256 seenMask; // bitmap for up to 256 members to block duplicates cheaply

        bytes32 ethHash = ECDSA.toEthSignedMessageHash(opId);

        for (uint256 i = 0; i < signers.length; i++) {
            address signer = signers[i];

            uint16 idxp1 = memberIndexPlus1[signer];
            if (idxp1 == 0) continue; // ignore non-members

            uint256 bit = 1 << (idxp1 - 1);
            if ((seenMask & bit) != 0) revert DuplicateSigner(signer);
            seenMask |= bit;

            if (_memberApproves(signer, opId, ethHash, sigs[i])) {
                valid++;
                if (valid >= threshold) return MAGICVALUE;
            }
        }

        return 0xffffffff;
    }

    function validateBundle(bytes32 opId, bytes calldata signature) external view returns (uint16 validCount) {
        if (signature.length == 0) {
            return uint16(_popcount(approvedMask[opId]));
        }

        (address[] memory signers, bytes[] memory sigs) = abi.decode(signature, (address[], bytes[]));
        if (signers.length != sigs.length) revert BadBundle();

        uint256 seenMask;
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(opId);

        for (uint256 i = 0; i < signers.length; i++) {
            address signer = signers[i];
            uint16 idxp1 = memberIndexPlus1[signer];
            if (idxp1 == 0) continue;

            uint256 bit = 1 << (idxp1 - 1);
            if ((seenMask & bit) != 0) continue; // ignore duplicates for debug view
            seenMask |= bit;

            if (_memberApproves(signer, opId, ethHash, sigs[i])) validCount++;
        }
    }

    /* ============================
       Internal
       ============================ */

    function _memberApproves(address member, bytes32 opId, bytes32 ethHash, bytes memory sig) internal view returns (bool) {
        if (member.code.length == 0) {
            // EOA member: expects personal_sign(opId) => ethHash
            address recovered = ECDSA.recover(ethHash, sig);
            return recovered == member;
        } else {
            // Contract member: EIP-1271 over raw opId (not ethHash)
            try IERC1271(member).isValidSignature(opId, sig) returns (bytes4 magic) {
                return magic == MAGICVALUE;
            } catch {
                return false;
            }
        }
    }

    function _setMembers(address[] memory members_, uint16 threshold_) internal {
        if (members_.length == 0) revert InvalidThreshold();
        if (members_.length > MAX_MEMBERS) revert TooManyMembers();

        // clear old
        for (uint256 i = 0; i < _members.length; i++) {
            memberIndexPlus1[_members[i]] = 0;
        }
        delete _members;

        // set new
        for (uint256 i = 0; i < members_.length; i++) {
            address m = members_[i];
            if (m == address(0)) revert ZeroAddress();
            if (memberIndexPlus1[m] != 0) revert AlreadyMember(m);

            _members.push(m);
            memberIndexPlus1[m] = uint16(i + 1);
            emit MemberAdded(m, i);
        }

        _validateThreshold(threshold_, _members.length);
        uint16 old = threshold;
        threshold = threshold_;
        emit ThresholdUpdated(old, threshold_);
    }

    function _validateThreshold(uint16 t, uint256 n) internal pure {
        // 1 <= threshold <= members.length
        if (t == 0 || t > n) revert InvalidThreshold();
    }

    function _popcount(uint256 x) internal pure returns (uint256 c) {
        // Kernighan popcount
        while (x != 0) {
            unchecked {
                x &= (x - 1);
                c++;
            }
        }
    }
}
