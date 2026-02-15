
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice ERC-1271 smart-wallet signature validation
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

library ECDSA {
    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        require(v == 27 || v == 28, "ECDSA: bad v");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "ECDSA: zero signer");
        return signer;
    }
}

contract DAIOControllerV1 {
    // ---- Branches (immutable “company”) ----
    address public immutable marketing;
    address public immutable community;
    address public immutable development;

    // ---- EIP-712 ----
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant OP_TYPEHASH =
        keccak256("Operation(address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)");

    bytes32 public immutable DOMAIN_SEPARATOR;

    // ---- Quorum ----
    // require >=2 distinct branches

    // ---- Nonce ----
    uint256 public nonce;

    // ---- Timelock (optional, DAO-level) ----
    uint256 public minDelay; // seconds (can be 0)
    mapping(bytes32 => uint256) public etaByOp;   // opId => earliest execution time
    mapping(bytes32 => bool) public doneByOp;     // opId => executed

    // ---- ERC-1271 magic ----
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;

    event Executed(bytes32 indexed opId, address indexed target, uint256 value);
    event Queued(bytes32 indexed opId, address indexed target, uint256 value, uint256 eta);
    event Cancelled(bytes32 indexed opId);
    event MinDelayUpdated(uint256 oldDelay, uint256 newDelay);

    modifier onlySelf() {
        require(msg.sender == address(this), "DAIO: only self");
        _;
    }

    constructor(
        address _marketing,
        address _community,
        address _development,
        uint256 _minDelay
    ) {
        require(_marketing != address(0) && _community != address(0) && _development != address(0), "DAIO: zero");
        require(_marketing != _community && _marketing != _development && _community != _development, "DAIO: dup");

        marketing = _marketing;
        community = _community;
        development = _development;

        minDelay = _minDelay;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("DAIOControllerV1")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    receive() external payable {}

    // -------- Core hashing --------

    function hashOperation(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 opNonce,
        uint256 deadline
    ) public view returns (bytes32 digest, bytes32 opId) {
        bytes32 dataHash = keccak256(data);
        bytes32 structHash = keccak256(abi.encode(OP_TYPEHASH, target, value, dataHash, opNonce, deadline));
        digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        opId = keccak256(abi.encode(target, value, dataHash, opNonce));
    }

    // -------- Signature verification (EOA or ERC-1271) --------

    function _isValidBranchSig(address branch, bytes32 digest, bytes calldata sig) internal view returns (bool) {
        if (branch.code.length == 0) {
            // EOA signature: signer must equal branch address
            address signer = ECDSA.recover(digest, sig);
            return signer == branch;
        } else {
            // ERC-1271 contract wallet
            try IERC1271(branch).isValidSignature(digest, sig) returns (bytes4 magic) {
                return magic == ERC1271_MAGIC;
            } catch {
                return false;
            }
        }
    }

    function _require2of3(bytes32 digest, bytes[] calldata sigs) internal view {
        // bitmask: 1=marketing, 2=community, 4=development
        uint256 mask;

        for (uint256 i = 0; i < sigs.length; i++) {
            bytes calldata sig = sigs[i];

            if ((mask & 1) == 0 && _isValidBranchSig(marketing, digest, sig)) {
                mask |= 1;
                continue;
            }
            if ((mask & 2) == 0 && _isValidBranchSig(community, digest, sig)) {
                mask |= 2;
                continue;
            }
            if ((mask & 4) == 0 && _isValidBranchSig(development, digest, sig)) {
                mask |= 4;
                continue;
            }
        }

        // popcount >= 2
        uint256 count = ((mask & 1) != 0 ? 1 : 0) + ((mask & 2) != 0 ? 1 : 0) + ((mask & 4) != 0 ? 1 : 0);
        require(count >= 2, "DAIO: need 2-of-3");
    }

    // -------- Immediate execution (no DAO timelock) --------

    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes[] calldata sigs
    ) external returns (bytes memory result) {
        require(block.timestamp <= deadline, "DAIO: expired");

        uint256 opNonce = nonce;
        (bytes32 digest, bytes32 opId) = hashOperation(target, value, data, opNonce, deadline);

        _require2of3(digest, sigs);

        nonce = opNonce + 1;

        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "DAIO: call failed");

        emit Executed(opId, target, value);
        return ret;
    }

    // -------- Queue + execute (DAO-level timelock) --------

    function queue(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes[] calldata sigs
    ) external returns (bytes32 opId, uint256 eta) {
        require(block.timestamp <= deadline, "DAIO: expired");

        uint256 opNonce = nonce;
        (bytes32 digest, bytes32 _opId) = hashOperation(target, value, data, opNonce, deadline);

        _require2of3(digest, sigs);

        nonce = opNonce + 1;

        eta = block.timestamp + minDelay;
        etaByOp[_opId] = eta;

        emit Queued(_opId, target, value, eta);
        return (_opId, eta);
    }

    function executeQueued(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 opNonce
    ) external returns (bytes memory result) {
        bytes32 dataHash = keccak256(data);
        bytes32 opId = keccak256(abi.encode(target, value, dataHash, opNonce));

        uint256 eta = etaByOp[opId];
        require(eta != 0, "DAIO: not queued");
        require(block.timestamp >= eta, "DAIO: timelock");
        require(!doneByOp[opId], "DAIO: done");

        doneByOp[opId] = true;

        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "DAIO: call failed");

        emit Executed(opId, target, value);
        return ret;
    }

    function cancel(bytes32 opId) external onlySelf {
        delete etaByOp[opId];
        emit Cancelled(opId);
    }

    // -------- Governance parameter (self-only) --------

    function setMinDelay(uint256 newDelay) external onlySelf {
        uint256 old = minDelay;
        minDelay = newDelay;
        emit MinDelayUpdated(old, newDelay);
    }
}
