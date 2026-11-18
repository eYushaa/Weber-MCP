"""Automated tests for Weber MCP's 4-layer Native OS & Process Sandbox."""

import asyncio
import json
import os
import subprocess
import winreg

import pytest

from weber_mcp.browser import DEFAULT_IDLE_TIMEOUT_SECONDS, HardenedBrowser
from weber_mcp.sandbox import SandboxViolationError, activate_sandbox
from weber_mcp.server import close_browser, weber_fetch_url, weber_sandbox_status


def test_windows_job_object_and_ui_restrictions() -> None:
    sandbox = activate_sandbox()
    assert sandbox.activated is True
    assert sandbox.job_active is True
    assert sandbox.ui_restrictions_active is True
    assert sandbox.config.max_job_memory_mb == 2048
    assert sandbox.config.max_active_processes == 32

    metrics = sandbox.get_job_metrics()
    assert metrics["job_active"] is True
    assert metrics["active_processes"] >= 1


def test_filesystem_jail_allows_inside_and_blocks_outside() -> None:
    sandbox = activate_sandbox()

    # Inside sandbox jail: create & delete must succeed
    jailed_file = os.path.join(sandbox.temp_dir, "allowed_temp.txt")
    with open(jailed_file, "w", encoding="utf-8") as fh:
        fh.write("safe inside jail")
    assert os.path.isfile(jailed_file)
    os.remove(jailed_file)
    assert not os.path.exists(jailed_file)

    # Outside jail (workspace): write must raise SandboxViolationError
    with pytest.raises(SandboxViolationError):
        with open("outside_jail_test.txt", "w", encoding="utf-8") as fh:
            fh.write("should not write")
    assert not os.path.exists("outside_jail_test.txt")

    # Outside jail: os.remove must raise SandboxViolationError (tested against non-existent path too)
    outside_target = os.path.join(os.getcwd(), "nonexistent_outside_target.txt")
    with pytest.raises(SandboxViolationError):
        os.remove(outside_target)

    # Outside jail (host user temp dir outside sandbox_root): write must raise SandboxViolationError
    host_temp_escape = os.path.join(sandbox.original_temp_dir, "weber_escape_test.txt")
    with pytest.raises(SandboxViolationError):
        with open(host_temp_escape, "w", encoding="utf-8") as fh:
            fh.write("escape")
    assert not os.path.exists(host_temp_escape)


def test_sensitive_credential_reads_blocked() -> None:
    activate_sandbox()
    with pytest.raises(SandboxViolationError):
        open(r"C:\Users\ahmet\.ssh\id_rsa", "r", encoding="utf-8")

    with pytest.raises(SandboxViolationError):
        open(r"C:\Windows\System32\config\SAM", "rb")


def test_arbitrary_process_and_shell_execution_blocked() -> None:
    activate_sandbox()

    with pytest.raises(SandboxViolationError):
        os.system("whoami")

    with pytest.raises(SandboxViolationError):
        subprocess.Popen(["cmd.exe", "/c", "echo", "hacked"])

    with pytest.raises(SandboxViolationError):
        subprocess.Popen(["powershell.exe", "-Command", "Get-Date"])

    # Spoofed command string attempting to mention playwright/node.exe as cmd.exe args
    with pytest.raises(SandboxViolationError):
        subprocess.Popen(["cmd.exe", "/c", "echo", "playwright", "node.exe"])


def test_windows_registry_modification_blocked() -> None:
    activate_sandbox()
    with pytest.raises(SandboxViolationError):
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\WeberSandboxTest")


def test_environment_secret_sanitization(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = activate_sandbox()
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-test-secret")

    clean_env, stripped_vars = sandbox.get_sanitized_env()
    assert "OPENAI_API_KEY" not in clean_env
    assert "AWS_SECRET_ACCESS_KEY" not in clean_env
    assert "OPENAI_API_KEY" in stripped_vars
    assert "AWS_SECRET_ACCESS_KEY" in stripped_vars
    assert clean_env.get("TEMP") == sandbox.temp_dir


@pytest.mark.asyncio
async def test_live_sandboxed_playwright_and_status_tool() -> None:
    try:
        status_json = await weber_sandbox_status()
        status = json.loads(status_json)
        assert status["activated"] is True
        assert status["layers"]["windows_job_object"]["active"] is True
        assert status["layers"]["python_audit_hook"]["active"] is True
        assert status["layers"]["filesystem_jail"]["active"] is True
        assert status["layers"]["env_sanitization"]["active"] is True
        assert status["browser_lifecycle"]["idle_timeout_seconds"] == DEFAULT_IDLE_TIMEOUT_SECONDS

        res = await weber_fetch_url("https://example.com")
        assert "Example Domain" in res
        assert "OS/Process Sandbox:" in res
        assert "JobObject=Active" in res
        assert "AuditHook=Active" in res
    finally:
        await close_browser()


@pytest.mark.asyncio
async def test_idle_timeout_auto_closes_browser_and_stealth_fingerprint() -> None:
    browser = HardenedBrowser(idle_timeout_seconds=0.3)
    try:
        async with browser._managed_context(java_script_enabled=True) as context:
            page = await context.new_page()
            webdriver_val = await page.evaluate("() => navigator.webdriver")
            plugins_len = await page.evaluate("() => navigator.plugins.length")
            has_chrome_runtime = await page.evaluate("() => Boolean(window.chrome && window.chrome.runtime)")
            languages = await page.evaluate("() => navigator.languages")

            assert not webdriver_val
            assert plugins_len >= 3
            assert has_chrome_runtime is True
            assert languages[0] == "tr-TR"

        # Immediately after context closes, browser stays warm until idle timeout expires
        assert browser.is_browser_running() is True

        # Wait past idle_timeout_seconds (0.3s) and confirm Chromium shuts down automatically
        await asyncio.sleep(0.55)
        assert browser.is_browser_running() is False
        assert browser.idle_shutdown_count == 1

        # Next request automatically wakes Chromium back up
        async with browser._managed_context(java_script_enabled=True) as context2:
            page2 = await context2.new_page()
            assert await page2.evaluate("() => navigator.platform") == "Win32"
            assert browser.is_browser_running() is True
    finally:
        await browser.close()
