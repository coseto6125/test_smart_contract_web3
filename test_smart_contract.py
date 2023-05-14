from decimal import Decimal
from allure import step, feature, attach, attachment_type, dynamic, title, story
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import ContractLogicError
from eth_account import Account
from solcx import compile_source, install_solc
from pytest import mark
from loguru import logger
from re import search
from subprocess import run as sub_run, PIPE

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

# > 定義測試用的智能合約
test_data = [
    [
        "正常測試",
        "0xA9CFBc5d3B44Ea9D3B2dE2b40aD2F9f8eC4e0f3F",
        "0x2E35F4A5DE521449d39821494dacC0d02B26075c",
        "0x6653ffd547b9210df04d7ddad92edb026d16d857849827539052a393949812c5",
        1,
    ],
    [
        "異常測試-接收轉帳帳號不存在",
        "0xA9CFBc5d3B44Ea9D3B2dE2b40aD2F9f8eC4e0f3F",
        "0x2E35F4A5DE521449d39821494dacC0d02B26075d",
        "0x6653ffd547b9210df04d7ddad92edb026d16d857849827539052a393949812c5",
        1,
    ],
    [
        "異常測試-餘額不足",
        "0xA9CFBc5d3B44Ea9D3B2dE2b40aD2F9f8eC4e0f3F",
        "0x2E35F4A5DE521449d39821494dacC0d02B26075c",
        "0x6653ffd547b9210df04d7ddad92edb026d16d857849827539052a393949812c5",
        10 << 18,
    ],
]


@feature("測試智能合約")
class TestSmartContract:
    contract_address = None
    web3 = None

    @classmethod
    def setup_class(cls):
        solc_ver = "0.8.2"
        contract_name = search("(?<=contract\s)\w+", contract_source)[0]
        rpc = "http://localhost:7545"

        with step(f"設定智能合約編譯器版本: {solc_ver}"):
            install_solc(solc_ver)
        with step(f"編譯智能合約: {contract_name}"):
            compiled_sol = compile_source(contract_source)
            contract_interface = compiled_sol[f"<stdin>:{contract_name}"]

        with step(f"連結到以太坊節點: {rpc}"):
            cls.web3 = Web3(Web3.HTTPProvider(rpc))

        with step("部署智能合約"):
            add1 = cls.web3.eth.accounts[0]
            SimpleTransfer = cls.web3.eth.contract(abi=contract_interface["abi"], bytecode=contract_interface["bin"])
            tx_hash = SimpleTransfer.constructor().transact({"from": add1})
            tx_receipt = cls.web3.eth.wait_for_transaction_receipt(tx_hash)
            cls.contract_address = tx_receipt.contractAddress

    @story("測試用例-slither 檢測智能合約問題")
    @title("測試用例-檢測智能合約問題")
    def test_slither_check(cls):
        """運行 Slither 工具來檢測智能合約中的問題並將輸出附加至附件。"""
        dynamic.description("運行 Slither 工具來檢測智能合約中的問題並將輸出附加至附件。")
        smc_path = "smart_contract.sol"
        with open(smc_path, "w", encoding="utf-8") as f:
            f.write(contract_source)
        result = sub_run(["slither", smc_path], stderr=PIPE)
        output = result.stderr.decode("utf-8")
        attach(output, "slither result", attachment_type=attachment_type.TEXT)
        assert not output, "slither檢測到智能合約有問題"

    @mark.parametrize("title, add1, add2, add1_private_key, amount", test_data)
    @title("測試用例-{title}")
    def test_my_contract(self, title, add1, add2, add1_private_key, amount):
        """
        此功能通過部署智能合約、驗證簽名、轉移資金和驗證生成的餘額來測試智能合約。

        Args:
          add1: `add1` 是一個代表賬戶以太坊地址的變量。
          add2: `add2` 是一個字符串，表示智能合約中轉賬接收方的以太坊地址。
          add1_private_key: 與地址 add1 關聯的以太坊帳戶的私鑰。
          amount: 智能合約測試中要轉移的以太幣數量。
        """
        dynamic.description(
            """
        此功能通過部署智能合約、驗證簽名、轉移資金和驗證生成的餘額來測試智能合約。

        Args:
          add1: `add1` 是一個代表賬戶以太坊地址的變量。
          add2: `add2` 是一個字符串，表示智能合約中轉賬接收方的以太坊地址。
          add1_private_key: 與地址 add1 關聯的以太坊帳戶的私鑰。
          amount: 智能合約測試中要轉移的以太幣數量。"""
        )

        def _print_balances(results):
            for idx, balance in enumerate(results):
                logger.info(f"add{idx} = {web3.from_wei(balance,'ether')}")
            return

        for i in [("add1", add1), ("add2", add2), ("add1_private_key", add1_private_key)]:
            dynamic.parameter(name=i[0], value=f"{i[1][:5]}...")
        if title == "正常測試":
            dynamic.story("正常測試")
        else:
            dynamic.story("異常測試")
        dynamic.parameter("title", title, mode="MASKED")
        web3 = self.web3
        contract_address = self.contract_address

        with step("設定智能合約編譯器版本"):
            install_solc("0.8.2")
        with step("編譯智能合約"):
            compiled_sol = compile_source(contract_source)
            contract_interface = compiled_sol["<stdin>:SimpleTransfer"]

        with step("部署智能合約"):
            add1 = web3.eth.accounts[0]
            SimpleTransfer = web3.eth.contract(abi=contract_interface["abi"], bytecode=contract_interface["bin"])
            tx_hash = SimpleTransfer.constructor().transact({"from": add1})
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            contract_address = tx_receipt.contractAddress

        with step("web3.py建立測試用資料"):
            with step("訊息雜湊"):
                message_hash = web3.keccak(text="Hello world")
                logger.debug("建立 訊息雜湊 完成")
            with step("使用私鑰簽署訊息"):
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
                assert (
                    tx_receipt["gasUsed"] == tx_receipt["cumulativeGasUsed"]
                ), "gasUsed is not equal to cumulativeGasUsed"
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
                assert tx_receipt["effectiveGasPrice"] > 0, "effectiveGasPrice is not greater than 0"
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
    # TestSmartContract().test_smart_contract()
    main()
