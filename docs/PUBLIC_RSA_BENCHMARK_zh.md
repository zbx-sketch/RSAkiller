# 公开 RSA CTF 基准进展

## 当前结论

当前证据不支持宣称达到 80%。manifest 包含 25 个固定案例，当前工具环境和本地依赖会影响分解结果；请以 `python -m RsaCtfTool.benchmark` 的新鲜运行输出为准。verified 集受攻击类型定向选择影响，并不是从完整赛事总体随机抽出的独立盲测题族。

| 轨道 | 案例数 | 结果 | 说明 |
|---|---:|---:|---|
| verified 回归集 | 23 | 以最近一次基准运行结果为准 | 每例校验输入 SHA-256、答案 SHA-256、攻击标签和数学闭环。 |
| development 案例 | 2 | 以最近一次基准运行结果为准 | 分解成功率依赖本地工具、依赖和资源预算。 |
| Google CTF 2023 crypto-lcg | 1 | 已包含在 verified | 恢复 8 个 512-bit 素因子，验证素因子乘积等于 n 且重新加密匹配。 |
| 本地 RSA 笔记 | 13 | 专项回归通过 | 与公开赛事基准分开计数。 |

## 证据

权威清单是 tests/fixtures/public_rsa/manifest.json，输入保存在同目录及 cryptohack/、pico/ 子目录。Google CTF 来源为官方 crypto-lcg 仓库。其输入 SHA-256 为 5f9d1ceb884ef0c656d7397250deaf243e34cb9dd67bdf961075fca9c1a2bb52，恢复明文 SHA-256 为 69981daf9abdebef789ff622d1672c37c6a1e97737415369dc77a4ba6360fd96。

基准测试对每例校验固定答案哈希和数学闭环；测试不向求解器提供答案文件或生成器私钥。manifest 记录输入哈希、攻击标签和来源 URL。公开样例夹具仅为可复现测试数据，不应将固定样例通过率表述为对全部 RSA CTF 题目的覆盖率。

## 覆盖率限制

这些公开案例均可被开发者访问，不是真正未知留出集。案例存在来源总体不完整、攻击类型定向选择以及相近弱点重复等问题。因此准确表述是“23 个固定 verified 实例通过”，不是“覆盖 80% 的公开 RSA CTF”。要支持统计性 80% 声明，需要冻结完整候选总体、按语义题族去重、预注册随机抽样、独立留出集和固定资源预算，并报告逐题结果与 95% Wilson 区间。

## 复现

    /home/rsauser/miniforge3/bin/conda run --no-capture-output -n sage python -m pytest -q tests/test_public_benchmark.py

运行基准前请先安装项目依赖。当前环境的测试结果不随发布包固定；CI 和本地运行的通过/失败数量应以对应 commit 的测试记录为准。
