# RsaCtfTool 本机网页界面

网页界面复用 RsaCtfTool 的原有攻击引擎，不需要单独安装 Web 框架。浏览器和攻击任务都运行在本机，服务只监听 `127.0.0.1`。

## 安装与启动

在仓库根目录运行：

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
rsactftool-web
```

启动器会打开 `http://127.0.0.1:8765/`。若浏览器没有自动打开，可手动访问该地址。按 Ctrl+C 停止服务。也可以运行：

```powershell
python -m RsaCtfTool.web --no-browser
python -m RsaCtfTool.web --port 9000
```

安装原项目依赖即可使用 CLI 和网页界面；SageMath 等可选后端仍需按原项目说明另外安装。

### 在 WSL 中使用 SageMath

如果要启用依赖 SageMath 的攻击，请从 WSL 的 Sage 环境启动网页界面。当前安装使用 Ubuntu 24.04 和 conda-forge SageMath：

```bash
wsl -d Ubuntu-24.04
conda activate sage
cd ~/RsaCtfTool
python -m RsaCtfTool.web --no-browser
```

也可以直接在 Windows 终端执行当前环境的一行启动命令：

```powershell
wsl -d Ubuntu-24.04 -- bash -lc 'cd /home/rsauser/RsaCtfTool && /home/rsauser/miniforge3/bin/conda run --no-capture-output -n sage python -m RsaCtfTool.web --no-browser'
```

然后在 Windows 浏览器中打开 `http://127.0.0.1:8765/`。需要停止时，在 WSL 窗口按 Ctrl+C。该环境还通过 WSL 包装器连接已安装的 YAFU 和 NECA；CLI 也可在同一 Sage 环境中运行。

## 使用

### 智能粘贴（一键，默认）

1. 将题面、附件文本、程序源码或运行输出整段粘贴到文本框；也可以选择不超过 1 MiB 的 `.txt`、`.py`、`.md` 文件。
2. 点击“智能解题”。工具会提取 `n/e/c/p/q/d/dp/dq` 以及多组带编号参数，判断攻击路径并做数学闭环验证。
3. 右侧报告会列出攻击依据、验证结果、明文候选、因子和私钥指数（若恢复成功）。

智能模式还会处理多组 `{n,e}`、Python 2 整数末尾的 `L`、受限数字字母表的进制推断、逐字符 RSA、十进制 ASCII 串接、题面中的 MD5 指令和常见比赛 Flag 前缀。粘贴内容被视为不可信文本：解析器只读取整数及公钥元组，**不会执行其中的 Python 或其他代码**。

当前笔记回归集覆盖 13 类真实题目：低指数直接开根、Håstad 广播、共模及非互素指数变体、批量共享素数、`dp` 泄漏、已知 `p/q`、无 `e` 的 `dp/dq` CRT 解密、小模数逐字符、相邻素数 Fermat、光滑 `p−1`、五进制输入、十进制 ASCII 拼接，以及 RSA 解密后的立方和方程恢复。逐题矩阵和验证条件见 [`docs/RSA_NOTE_COVERAGE_zh.md`](docs/RSA_NOTE_COVERAGE_zh.md)。

### 手动高级

1. 切换到“手动高级”，上传 PEM / OpenSSH 公钥文件，或填写 `n` 和 `e`。十进制与 `0x` 十六进制整数均可。
2. 选择“尝试恢复私钥”或“尝试解密”。解密时输入十进制、`0x` 十六进制或 Base64 密文；若多个密文用英文逗号分隔。
3. 默认攻击集排除了 Factordb、WolframAlpha 等在线服务。选择“全部攻击”可能把模数发送给第三方服务；使用此模式前请确认密钥数据适合外传。
4. 可选地设置攻击超时、并行数和专项攻击参数。

“推荐：本地攻击”和“全部攻击”会根据已填写的 `n`、`e`、密文数量以及专项参数自动调整顺序：例如多个指数和密文会优先尝试共模攻击，填写 `dp/dq` 会优先尝试 `dp_leak`，填写部分 `p` 信息会优先尝试 `partial_p`。自选模式则按用户勾选的攻击运行。

“并行攻击数”可填写 1–10。大于 1 时，工具按批次启动独立进程。只请求解密时，若多密钥共模攻击已恢复明文，工具会跳过后续逐密钥分解；请求私钥时，若先拿到明文，界面会显示“明文已恢复；私钥仍在尝试”，并继续尝试恢复私钥。结果区的“停止攻击”按钮可以结束当前任务。

恢复私钥且模数至少 512 位时，如果所选攻击包含 YAFU 并且系统已安装 YAFU，网页会在后台单独运行 YAFU 分解，同时继续其他攻击；这样并行攻击数为 1 时也能继续尝试其他方法，并且不会重复运行 YAFU。建议普通电脑使用 2–4；YAFU、SageMath、NECA 等外部后端较多时使用 1–2。网页结果只保留成功攻击、私钥和明文等有用信息。

### 相同 n 的多个指数（Common Modulus）

题目给出同一个 `n`、多个 `e` 和对应密文时，切换到“填写 n 和 e”，在 `n` 中填写一次模数，在 `e` 中按顺序填写逗号分隔的指数，例如 `17,65537`。然后切换到“尝试解密”，把对应密文按相同顺序用英文逗号分隔填写，例如 `c1,c2`。在“攻击方式”中选择“自选攻击方式”，勾选 `common_modulus_related_message`，再运行分析。该攻击利用相同模数和互质指数恢复明文，不需要先分解 `n`。

网页提交的参数等价于以下命令行形式（命令行本身仍支持原有用法）：

```bash
python -m RsaCtfTool -n "<n>" -e "17,65537" \
  --decrypt "<c1>,<c2>" \
  --attack common_modulus_related_message
```

表单请求最多 3 MiB，题目文本最多 1,000,000 个字符，公钥/题目文件最多 1 MiB，手动解密文本最多 100,000 个字符；同一时间只运行一个攻击任务。输出最多保留 1,000,000 个字符。

## 命令行

原有的 `RsaCtfTool`、`rsacrack` 和 `python -m RsaCtfTool` 命令保持不变。智能解析器也可以单独使用：

```bash
python -m RsaCtfTool.ctf_solver --input challenge.txt --timeout 120
```

进程退出码为 `0` 表示至少获得一个通过闭环验证的结果，`1` 表示没有恢复出可验证明文，`2` 表示输入文件读取失败。
