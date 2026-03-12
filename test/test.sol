// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleVault
 * @notice 用于测试：包含注释/空行/事件/修饰器等，便于观察预处理效果
 */
contract SimpleVault {
    address public owner;

    mapping(address => uint256) private balances;

    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // 存款：任意人可存
    function deposit() external payable {
        require(msg.value > 0, "zero");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @dev 提款：仅 owner 可提走指定用户余额（演示用，不是最佳实践）
     */
    function withdrawFor(address user) external onlyOwner {
        uint256 amount = balances[user];
        require(amount > 0, "empty");

        balances[user] = 0;

        (bool ok, ) = payable(owner).call{value: amount}("");
        require(ok, "transfer failed");

        emit Withdrawn(owner, amount);
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }
}