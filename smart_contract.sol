
pragma solidity ^0.8.2;

contract SimpleTransfer {
    event Transfer(address indexed from, address indexed to, uint256 value);

    function transfer(bytes32 messageHash, bytes memory signature, address payable to) public payable {
    require(verifySignature(messageHash, signature, msg.sender) == true, "Invalid signature");
    require(address(this).balance >= msg.value, "Insufficient balance");
    to.transfer(msg.value);
    emit Transfer(msg.sender, to, msg.value);
    }

    function verifySignature(bytes32 messageHash, bytes memory signature, address expectedAddress) public pure returns (bool) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature recovery value");

        address signer = ecrecover(messageHash, v, r, s);
        return (signer == expectedAddress);
    }

    function getBalances(address addr1, address addr2) public view returns (uint256, uint256) {
        return (addr1.balance, addr2.balance);
    }
}
