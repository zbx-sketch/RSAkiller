import http.client
import json
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from RsaCtfTool import web


def test_recommended_attacks_are_local_and_do_not_need_extra_parameters():
    command = web.build_cli_args({"n": "0x12345", "e": "65537"})
    attack_start = command.index("--attack") + 1
    selected = command[attack_start : attack_start + len(web.local_attacks())]

    assert selected == web.local_attacks()
    assert "factordb" not in selected
    assert "wolframalpha" not in selected
    assert "nullattack" not in web.discover_attacks()
    assert "same_n_huge_e" not in web.discover_attacks()
    assert not (set(selected) & web.ATTACKS_REQUIRING_EXTRA_INPUT)
    assert "--private" in command
    assert "--cleanup" in command


def test_custom_decrypt_args_are_passed_as_arguments_not_shell_text():
    command = web.build_cli_args(
        {
            "n": "123456789",
            "e": "65537",
            "mode": "decrypt",
            "ciphertext": "0x2a",
            "attack_mode": "custom",
            "attacks": ["wiener"],
            "timeout": 30,
        }
    )

    assert "--attack" in command
    assert command[command.index("--attack") + 1] == "wiener"
    assert "--decrypt=0x2a" in command
    assert "--private" not in command
    assert "--timeout" in command and command[command.index("--timeout") + 1] == "30"


def test_common_modulus_web_args_accept_multiple_exponents_and_ciphers():
    command = web.build_cli_args(
        {
            "n": "123456789",
            "e": "17, 65537",
            "mode": "decrypt",
            "ciphertext": "123,456",
            "attack_mode": "custom",
            "attacks": ["common_modulus_related_message"],
        }
    )

    assert command[command.index("-e") + 1] == "17,65537"
    assert command[command.index("--decrypt=123,456")] == "--decrypt=123,456"
    assert "common_modulus_related_message" in command


def test_smart_paste_command_is_file_based_and_strictly_validated(tmp_path):
    challenge_path = tmp_path / "challenge.txt"
    challenge_path.write_text("n = 33\ne = 3\nc = 8\n", encoding="utf-8")
    command = web.build_smart_cli_args(
        {"challenge_text": challenge_path.read_text(), "timeout": "45"},
        challenge_path,
    )

    assert command[:4] == [web.sys.executable, "-u", "-m", "RsaCtfTool.ctf_solver"]
    assert command[command.index("--input") + 1] == str(challenge_path)
    assert command[command.index("--timeout") + 1] == "45"
    assert "n = 33" not in command
    with pytest.raises(web.RequestError, match="请粘贴"):
        web.build_smart_cli_args({"challenge_text": "   "}, challenge_path)
    with pytest.raises(web.RequestError, match="1,000,000"):
        web.build_smart_cli_args(
            {"challenge_text": "1" * (web.MAX_CHALLENGE_CHARS + 1)},
            challenge_path,
        )


def test_smart_paste_job_keeps_full_verified_report():
    plaintext = int.from_bytes(b"web-smart-ok", "big")
    ciphertext = plaintext**3
    payload = {
        "challenge_text": f"n = {ciphertext + 12345}\ne = 3\nc = {ciphertext}\n",
        "timeout": 20,
    }
    store = web.JobStore()
    try:
        job = store.submit(payload)
        deadline = time.monotonic() + 10
        while job["status"] == "running" and time.monotonic() < deadline:
            time.sleep(0.02)
            job = store.get(job["id"])
        assert job["status"] == "finished"
        assert job["exit_code"] == 0
        assert "direct_low_exponent_root" in job["output"]
        assert "web-smart-ok" in job["output"]
        assert "重新加密" not in job["output"] or "True" in job["output"]
        assert "安全说明" in job["output"]
    finally:
        store.shutdown()


def test_smart_and_manual_fields_cannot_be_mixed():
    store = web.JobStore()
    with pytest.raises(web.RequestError, match="不能同时提交"):
        store.submit({"challenge_text": "n=33", "n": "33", "e": "3"})


def test_common_modulus_web_args_reject_empty_exponent_entries():
    with pytest.raises(web.RequestError):
        web.build_cli_args(
            {
                "n": "123456789",
                "e": "17,,65537",
                "mode": "decrypt",
                "ciphertext": "123,456",
                "attack_mode": "custom",
                "attacks": ["common_modulus_related_message"],
            }
        )


def test_parameter_aware_priority_is_passed_for_local_and_all_modes():
    payload = {
        "n": "123456789",
        "e": "17,65537",
        "mode": "decrypt",
        "ciphertext": "123,456",
    }
    command = web.build_cli_args(payload)
    assert "--attack-priority" in command
    priority = command[command.index("--attack-priority") + 1].split(",")
    assert priority[0] == "common_modulus_related_message"

    all_command = web.build_cli_args({**payload, "attack_mode": "all"})
    assert "--attack-priority" in all_command
    assert all_command[all_command.index("--attack") + 1] == "all"


def test_parameter_aware_priority_prefers_explicit_leaks():
    priority = web.recommend_attack_priority(
        {
            "n": "123456789",
            "e": "65537",
            "dp": "42",
            "p_high": "0x12",
            "p_unknown_bits": "32",
        },
        web.discover_attacks(),
    )
    assert priority[:2] == ["dp_leak", "partial_p"]


def test_parallel_worker_count_is_validated_and_output_is_concise():
    command = web.build_cli_args(
        {"n": "12345", "e": "65537", "parallel_workers": "10"}
    )
    assert "--attack-priority" in command or "--attack" in command
    with pytest.raises(web.RequestError):
        web.build_cli_args({"n": "12345", "e": "65537", "parallel_workers": "11"})
    with pytest.raises(web.RequestError):
        web.build_cli_args({"n": "12345", "e": "65537", "parallel_workers": "0"})

    prioritized = web.build_cli_args(
        {
            "n": "12345",
            "e": "17,65537",
            "mode": "decrypt",
            "ciphertext": "1,2",
            "parallel_workers": "3",
        }
    )
    assert (
        web.JobStore._command_attacks(prioritized)[0]
        == "common_modulus_related_message"
    )

    output = web.concise_attack_output(
        "\x1b[38;21m[*] Testing key C:\\Temp\\tmp.pub.\x1b[0m\n"
        "[*] Performing wiener attack.\n"
        "[*] Attack success with wiener method !\n"
        "utf-8 : flag{ok}\n"
    )
    assert output == "攻击成功：wiener\n\n明文：flag{ok}\n"
    assert "Testing key" not in output
    assert "\x1b" not in output


def test_plaintext_output_includes_the_attack_name_without_cli_success_marker():
    output = web.concise_attack_output(
        "[*] Performing common_modulus_related_message attack.\n"
        "Sorry, cracking failed.\n"
        "Decrypted data :\n"
        "utf-8 : flag{common_modulus_attack}\n"
    )
    assert output == (
        "攻击成功：common_modulus_related_message（RSA 共模相关消息）（已恢复明文）"
        "\n\n明文：flag{common_modulus_attack}\n"
    )


def test_plaintext_does_not_count_as_private_key_success():
    assert web._has_plaintext("Decrypted data :\nutf-8 : flag{x}\n")
    assert not web.JobStore._output_is_success(
        "Attack success with common_modulus_related_message method\n"
        "utf-8 : flag{x}\n",
        private_requested=True,
    )
    assert web.JobStore._output_is_success(
        "Private key :\n-----BEGIN RSA PRIVATE KEY-----\n",
        private_requested=True,
    )


def test_large_modulus_private_job_runs_yafu_in_background_and_stop_kills_both(
    monkeypatch,
):
    both_started = threading.Event()
    release = threading.Event()
    processes = []
    commands = []

    class FakeProcess:
        def __init__(self, index):
            self.returncode = None
            self.index = index
            self.terminated = False

        def poll(self):
            return self.returncode

        def communicate(self):
            release.wait(timeout=2)
            return "", None

        def terminate(self):
            self.terminated = True
            self.returncode = -15
            release.set()

    def fake_popen(command, **kwargs):
        commands.append(command)
        process = FakeProcess(len(processes))
        processes.append(process)
        if len(processes) == 2:
            both_started.set()
        return process

    monkeypatch.setattr(web.shutil, "which", lambda name: "/usr/bin/yafu")
    monkeypatch.setattr(web.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        web.JobStore, "_terminate_process", lambda self, process: process.terminate()
    )
    store = web.JobStore()
    job = store.submit(
        {
            "n": str(1 << 511),
            "e": "65537",
            "attack_mode": "custom",
            "attacks": ["yafu", "wiener"],
            "parallel_workers": 1,
        }
    )
    assert both_started.wait(timeout=2)
    live_job = store.get(job["id"])
    assert "后台使用 YAFU" in live_job["output"]
    assert len(processes) == 2
    assert "yafu" in commands[0]
    assert "yafu" not in commands[1]

    store.cancel(job["id"])
    deadline = time.monotonic() + 2
    final_job = store.get(job["id"])
    while final_job["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
        final_job = store.get(job["id"])

    assert final_job["status"] == "cancelled"
    assert all(process.terminated for process in processes)


def test_single_worker_keeps_plaintext_visible_while_yafu_runs_in_background(
    monkeypatch,
):
    all_started = threading.Event()
    release = threading.Event()
    processes = []
    commands = []

    class FakeProcess:
        def __init__(self, index):
            self.index = index
            self.returncode = 1 if index == 1 else None
            self.terminated = False

        def poll(self):
            return self.returncode

        def communicate(self):
            if self.index == 1:
                return (
                    "[*] Performing common_modulus_related_message attack.\n"
                    "Decrypted data :\nutf-8 : flag{found}\n",
                    None,
                )
            release.wait(timeout=5)
            return "", None

        def terminate(self):
            self.terminated = True
            self.returncode = -15
            release.set()

    def fake_popen(command, **kwargs):
        commands.append(command)
        process = FakeProcess(len(processes))
        processes.append(process)
        if len(processes) == 3:
            all_started.set()
        return process

    monkeypatch.setattr(web.shutil, "which", lambda name: "/usr/bin/yafu")
    monkeypatch.setattr(web.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        web.JobStore, "_terminate_process", lambda self, process: process.terminate()
    )
    store = web.JobStore()
    job = store.submit(
        {
            "n": str(1 << 511),
            "e": "17,65537",
            "attack_mode": "custom",
            "attacks": ["yafu", "common_modulus_related_message", "wiener"],
            "parallel_workers": 1,
        }
    )
    assert all_started.wait(timeout=2)
    live_job = store.get(job["id"])
    assert "明文已恢复；私钥仍在尝试。" in live_job["output"]
    assert "flag{found}" in live_job["output"]
    assert "yafu" in commands[0]
    assert "yafu" not in commands[1]
    assert "yafu" not in commands[2]

    store.cancel(job["id"])
    deadline = time.monotonic() + 2
    final_job = store.get(job["id"])
    while final_job["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
        final_job = store.get(job["id"])

    assert final_job["status"] == "cancelled"
    assert processes[0].terminated
    assert processes[2].terminated


def test_parallel_private_job_shows_plaintext_while_private_key_search_continues(
    monkeypatch,
):
    second_started = threading.Event()
    release_second = threading.Event()
    processes = []

    class FakeProcess:
        def __init__(self, index):
            self.index = index
            self.returncode = 1 if index == 0 else None

        def communicate(self):
            if self.index == 0:
                return (
                    "[*] Performing common_modulus_related_message attack.\n"
                    "Decrypted data :\nutf-8 : flag{found}\n",
                    None,
                )
            release_second.wait(timeout=5)
            self.returncode = 1
            return "[*] Performing wiener attack.\n", None

        def poll(self):
            return self.returncode

    def fake_popen(*args, **kwargs):
        process = FakeProcess(len(processes))
        processes.append(process)
        if len(processes) == 2:
            second_started.set()
        return process

    monkeypatch.setattr(web.subprocess, "Popen", fake_popen)
    store = web.JobStore()
    job = store.submit(
        {
            "n": "123456789",
            "e": "17,65537",
            "attack_mode": "custom",
            "attacks": ["common_modulus_related_message", "wiener"],
            "parallel_workers": 2,
        }
    )
    assert second_started.wait(timeout=2)
    live_job = store.get(job["id"])
    deadline = time.monotonic() + 2
    while (
        "明文已恢复；私钥仍在尝试。" not in live_job["output"]
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
        live_job = store.get(job["id"])
    assert "明文已恢复；私钥仍在尝试。" in live_job["output"]
    assert "flag{found}" in live_job["output"]

    release_second.set()
    deadline = time.monotonic() + 2
    final_job = store.get(job["id"])
    while final_job["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
        final_job = store.get(job["id"])

    assert final_job["status"] == "finished"
    assert "flag{found}" in final_job["output"]
    assert "明文已恢复；私钥仍在尝试。" not in final_job["output"]


def test_hex_input_is_normalized_and_bit_lengths_remain_decimal():
    command = web.build_cli_args(
        {
            "n": "0X12345",
            "e": "65537",
            "attack_mode": "custom",
            "attacks": ["partial_p"],
            "p_high": "0X12",
            "p_unknown_bits": "128",
        }
    )

    assert command[command.index("-n") + 1] == "0x12345"
    assert command[command.index("--p-high") + 1] == "0x12"
    assert command[command.index("--p-unknown-bits") + 1] == "128"
    with pytest.raises(web.RequestError, match="十进制整数"):
        web.build_cli_args(
            {
                "n": "12345",
                "e": "65537",
                "attack_mode": "custom",
                "attacks": ["partial_p"],
                "p_unknown_bits": "0x80",
            }
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"n": "1; whoami", "e": "65537"},
        {"n": "12345", "e": "65537", "attack_mode": "custom", "attacks": [{"bad": 1}]},
        {
            "n": "12345",
            "e": "65537",
            "attack_mode": "custom",
            "attacks": ["not_an_attack"],
        },
        {"n": "12345", "e": "65537", "timeout": 0},
    ],
)
def test_invalid_form_values_are_rejected(payload):
    with pytest.raises(web.RequestError):
        web.build_cli_args(payload)


def test_upload_data_is_strictly_decoded_and_size_limited():
    assert web._upload_bytes({"name": "key.pem", "data": "cGVt"}, "公钥") == b"pem"
    with pytest.raises(web.RequestError):
        web._upload_bytes({"name": "key.pem", "data": "%%%"}, "公钥")


def test_public_key_upload_uses_the_server_staged_file(tmp_path):
    key_path = tmp_path / "public-key.pem"
    key_path.write_text("test key", encoding="utf-8")
    command = web.build_cli_args({"mode": "recover"}, key_path)

    assert command[command.index("--publickey") + 1] == str(key_path)
    assert "-n" not in command
    assert "-e" not in command


def test_job_streams_output_and_rejects_a_second_running_task(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    calls = []

    class FakeProcess:
        returncode = None

        def __init__(self):
            def output_lines():
                yield "\x1b[38;21m[*] Performing wiener attack.\x1b[0m\n"
                started.set()
                assert release.wait(timeout=2)

            self.stdout = output_lines()

        def wait(self):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15
            release.set()

    def fake_popen(command, **kwargs):
        calls.append((command, kwargs))
        return FakeProcess()

    monkeypatch.setattr(web.subprocess, "Popen", fake_popen)
    store = web.JobStore()
    try:
        job = store.submit({"n": "12345", "e": "65537"})
        assert started.wait(timeout=2)
        live_job = store.get(job["id"])
        assert live_job["status"] == "running"
        assert "正在尝试攻击：wiener（Wiener 小 d）" in live_job["output"]
        with pytest.raises(web.RequestError, match="已有任务正在运行"):
            store.submit({"n": "12345", "e": "65537"})
    finally:
        release.set()

    deadline = time.monotonic() + 2
    final_job = store.get(job["id"])
    while final_job["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
        final_job = store.get(job["id"])

    assert final_job["status"] == "finished"
    assert final_job["exit_code"] == 0
    assert "未恢复出私钥或明文" in final_job["output"]
    command, options = calls[0]
    assert options["shell"] is False
    assert command[:3] == [web.sys.executable, "-m", "RsaCtfTool"]


def test_running_job_can_be_cancelled(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    processes = []

    class FakeProcess:
        def __init__(self):
            self.returncode = None
            self.terminated = False

            def output_lines():
                yield "[*] Performing wiener attack.\n"
                started.set()
                release.wait(timeout=2)

            self.stdout = output_lines()

        def poll(self):
            return self.returncode

        def wait(self):
            release.wait(timeout=2)
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15
            release.set()

    def fake_popen(*args, **kwargs):
        process = FakeProcess()
        processes.append(process)
        return process

    monkeypatch.setattr(web.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        web.JobStore, "_terminate_process", lambda self, process: process.terminate()
    )
    store = web.JobStore()
    job = store.submit({"n": "12345", "e": "65537"})
    assert started.wait(timeout=2)

    stopping = store.cancel(job["id"])
    assert stopping["status"] == "running"
    assert stopping["cancel_requested"] is True
    assert "正在停止攻击" in stopping["output"]

    deadline = time.monotonic() + 2
    final_job = store.get(job["id"])
    while final_job["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
        final_job = store.get(job["id"])

    assert final_job["status"] == "cancelled"
    assert final_job["exit_code"] is None
    assert final_job["output"] == "用户已停止攻击。\n"
    assert processes[0].terminated is True



@pytest.mark.parametrize("parallel_workers", [1, 2])
def test_job_wallclock_timeout_kills_blocked_process(monkeypatch, parallel_workers):
    started = threading.Event()
    release = threading.Event()
    processes = []

    class FakeProcess:
        def __init__(self):
            self.returncode = None
            self.terminated = False
            class BlockingStdout:
                def __iter__(self):
                    return self

                def __next__(self):
                    started.set()
                    release.wait(timeout=3)
                    raise StopIteration

            self.stdout = BlockingStdout()

        def poll(self):
            return self.returncode

        def communicate(self):
            started.set()
            release.wait(timeout=3)
            return "", None

        def terminate(self):
            self.terminated = True
            self.returncode = -15
            release.set()

        def wait(self, timeout=None):
            if self.returncode is None:
                release.wait(timeout=timeout or 3)
            return self.returncode

    def fake_popen(*args, **kwargs):
        process = FakeProcess()
        processes.append(process)
        return process

    monkeypatch.setattr(web.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(web.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        web.JobStore, "_terminate_process", lambda self, process: process.terminate()
    )
    store = web.JobStore()
    job = store.submit({
        "n": "3233", "e": "17", "c": "2790", "timeout": 1,
        "attack_mode": "custom", "attacks": ["wiener", "fermat"],
        "parallel_workers": parallel_workers,
    })
    assert started.wait(timeout=2)
    deadline = time.monotonic() + 3
    final_job = store.get(job["id"])
    while final_job["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.02)
        final_job = store.get(job["id"])
    assert final_job["status"] == "timeout"
    assert final_job["cancel_requested"] is False
    assert processes and all(process.terminated for process in processes)


def test_parallel_job_cancellation_stops_every_child_before_next_batch(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    processes = []

    class FakeProcess:
        def __init__(self):
            self.returncode = None
            self.terminated = False

        def poll(self):
            return self.returncode

        def communicate(self):
            release.wait(timeout=2)
            return "", None

        def terminate(self):
            self.terminated = True
            self.returncode = -15
            release.set()

    def fake_popen(*args, **kwargs):
        process = FakeProcess()
        processes.append(process)
        if len(processes) == 2:
            started.set()
        return process

    monkeypatch.setattr(web.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        web.JobStore, "_terminate_process", lambda self, process: process.terminate()
    )
    store = web.JobStore()
    job = store.submit(
        {
            "n": "12345",
            "e": "65537",
            "attack_mode": "custom",
            "attacks": ["wiener", "fermat", "brent"],
            "parallel_workers": 2,
        }
    )
    assert started.wait(timeout=2)
    store.cancel(job["id"])

    deadline = time.monotonic() + 2
    final_job = store.get(job["id"])
    while final_job["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
        final_job = store.get(job["id"])

    assert final_job["status"] == "cancelled"
    assert len(processes) == 2
    assert all(process.terminated for process in processes)


def test_http_interface_serves_ui_and_rejects_non_local_host_headers():
    store = web.JobStore()
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.create_handler(store))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "RsaCtfTool · 本机工作台" in body
        assert "智能粘贴（一键）" in body
        assert 'id="challenge-text"' in body
        assert "不会执行你粘贴的题目代码" in body
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        connection.request("GET", "/api/attacks")
        response = connection.getresponse()
        attacks = json.loads(response.read().decode("utf-8"))
        assert response.status == 200
        assert "factordb" not in attacks["local_attacks"]
        assert attacks["attack_labels"]["wiener"] == "Wiener 小 d"
        assert attacks["attack_labels"]["common_modulus_related_message"] == (
            "RSA 共模相关消息"
        )
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        connection.request(
            "POST",
            "/api/run",
            body=json.dumps({"n": "not-an-integer", "e": "65537"}),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        assert response.status == 400
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        connection.request("POST", "/api/jobs/deadbeef/cancel")
        response = connection.getresponse()
        assert response.status == 404
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        connection.request("GET", "/api/attacks", headers={"Host": "attacker.example"})
        response = connection.getresponse()
        assert response.status == 403
        assert (
            "仅接受本机浏览器连接"
            in json.loads(response.read().decode("utf-8"))["error"]
        )
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
