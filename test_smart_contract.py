from decimal import Decimal
from allure import title, step, feature
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import ContractLogicError
from eth_account import Account
from solcx import compile_source, install_solc
from loguru import logger
from orjson import dumps,OPT_SERIALIZE_NUMPY,OPT_NAIVE_UTC
# > 連接到測試用的以太坊節點
web3 = Web3(Web3.HTTPProvider("http://localhost:7545"))

# > 編譯測試用solidity智能合約
contract_source = """
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
"""


@feature("測試智能合約")
class TestSmartContract:

    @title("測試智能合約")
    def test_smart_contract(self):
        def _print_balances(results):
            for idx, balance in enumerate(results):
                logger.info(f"add{idx} = {web3.from_wei(balance,'ether')}")
            return

        amount = 1  # 轉帳金額 (ether)
        add1_private_key = "0x68397f6f4c487120af14452bdebdcf8403080cfdd124c2f889ef1a810f701940"

        with step("設定智能合約編譯器版本"):
            install_solc("0.8.2")
        with step("編譯智能合約"):
            compiled_sol = compile_source(contract_source)
            contract_interface = compiled_sol["<stdin>:SimpleTransfer"]

        with step("部署智能合約"):
            add1, add2 = web3.eth.accounts[0:2]
            SimpleTransfer = web3.eth.contract(abi=contract_interface["abi"], bytecode=contract_interface["bin"])
            tx_hash = SimpleTransfer.constructor().transact({"from": add1})
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            contract_address = tx_receipt.contractAddress

        with step("web3.py建立測試用資料"):
            with step("訊息雜湊"):
                message_hash = web3.keccak(text="Hello world")
                logger.debug("建立 訊息雜湊 完成")
            with step("使用私鑰簽署訊息"):
                add1_private_key = "0x68397f6f4c487120af14452bdebdcf8403080cfdd124c2f889ef1a810f701940"
                signed_message = Account.signHash(message_hash, private_key=add1_private_key)
                logger.debug("使用 私鑰簽署訊息 完成")
            with step("取得簽名"):
                signature = signed_message.signature
                logger.debug("建立 智能合約實例 完成")
            with step("建立智能合約實例"):
                simple_transfer = web3.eth.contract(address=contract_address, abi=contract_interface["abi"])

        with step("透過智能合約 getBalance 顯示原有餘額"):
            result_before = simple_transfer.functions.getBalances(add1, add2).call()
            _print_balances(result_before)

        with step("透過智能合約呼叫 驗證簽名 函數"):
            is_valid = simple_transfer.functions.verifySignature(message_hash, signature, add1).call()
            assert is_valid is True, "驗證簽名正確性"

        with step("呼叫合約 轉帳 函數"):
            try:
                transfer_hash = simple_transfer.functions.transfer(message_hash, signature, add2).transact(
                    {"from": add1, "value": web3.to_wei(amount, "ether")}
                )
                tx_receipt_transfer = web3.eth.wait_for_transaction_receipt(transfer_hash)
            except ContractLogicError as e:
                logger.warning(e)

            with step("驗證 transactionHash: 交易的哈希值。"):
                assert isinstance(tx_receipt["transactionHash"], HexBytes), "transactionHash is not a HexBytes object"
            with step("驗證 transactionIndex: 交易在區塊中的索引位置。"):
                assert isinstance(tx_receipt["transactionIndex"], int), "transactionIndex is not an integer"
            with step("驗證 blockNumber: 包含交易的區塊號。"):
                assert isinstance(tx_receipt["blockNumber"], int), "blockNumber is not an integer"
            with step("驗證 blockHash: 包含交易的區塊的哈希值。"):
                assert isinstance(tx_receipt["blockHash"], HexBytes), "blockHash is not a HexBytes object"
            with step("驗證 from: 交易的發件人地址。"):
                assert isinstance(tx_receipt["from"], str), "from is not a string"
                assert tx_receipt["from"] == add1, "from is not equal to add1"
            with step("驗證 to: 交易的收件人地址，如果這是一個合約創建交易，則為 None。"):
                assert tx_receipt["to"] is None, "to is not None"
            with step("驗證 cumulativeGasUsed: 到目前為止在區塊中累計消耗的 gas 數量。"):
                assert isinstance(tx_receipt["cumulativeGasUsed"], int), "cumulativeGasUsed is not an integer"
            with step("驗證 gasUsed: 交易消耗的 gas 數量。"):
                assert isinstance(tx_receipt["gasUsed"], int), "gasUsed is not an integer"
                assert tx_receipt["gasUsed"] == tx_receipt["cumulativeGasUsed"], "gasUsed is not equal to cumulativeGasUsed"
            with step("驗證 contractAddress: 如果這是一個合約創建交易，則包含新創建合約的地址，否則為 None。"):
                assert isinstance(tx_receipt["contractAddress"], str), "contractAddress is not a string"
            with step("驗證 logs: 交易引發的事件數組。"):
                assert isinstance(tx_receipt["logs"], list), "logs is not a list"
            with step("驗證 logsBloom: 交易引發的事件數組的布隆過濾器。"):
                assert isinstance(tx_receipt["logsBloom"], HexBytes), "logsBloom is not a HexBytes object"
            with step("驗證 status: 交易的狀態，1 表示成功，0 表示失敗。"):
                assert isinstance(tx_receipt["status"], int), "status is not an integer"
            with step("驗證 effectiveGasPrice: 交易的實際 gas 價格。"):
                assert isinstance(tx_receipt["effectiveGasPrice"], int), "effectiveGasPrice is not an integer"
                assert tx_receipt["effectiveGasPrice"]>0, "effectiveGasPrice is not greater than 0"
            with step("驗證 type: 交易的類型，0 表示普通轉賬交易，1 表示合約創建交易，2 表示合約調用交易。"):
                assert isinstance(tx_receipt["type"], int), "type is not an integer"
                assert tx_receipt["type"] == 2, "type is not equal to 2"

            # 透過智能合約 getBalance 顯示變動後餘額
            result_after = simple_transfer.functions.getBalances(add1, add2).call()
            total_cost = tx_receipt_transfer["gasUsed"] * tx_receipt_transfer["effectiveGasPrice"] + web3.to_wei(
                amount, "ether"
            )
            from pprint import pformat

            dcm = lambda x: Decimal(str(x))
            logger.info(f"add1 total cost = {total_cost}")
            with step("驗證add1 交易後金額正確"):
                assert dcm(result_after[0]) + total_cost == result_before[0], "add1 轉帳後餘額正確"
            with step("驗證add2 交易後金額正確"):
                assert result_after[1] - web3.to_wei(amount, "ether") == result_before[1], "add2 轉帳後餘額正確"
            _print_balances(result_after)
            logger.info("-----\n")
            logger.info(pformat(dict(tx_receipt_transfer)))
            logger.info("-----")
            logger.success("test smart contract success")


def main():
    from os import system

    system("pytest test_smart_contract.py --alluredir=./reports/")
    system("allure generate ./reports/ --clean -o ./reports_html/")


if __name__ == "__main__":
    TestSmartContract().test_smart_contract()
    main()

