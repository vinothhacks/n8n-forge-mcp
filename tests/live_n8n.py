"""Exercise the production-guarded stdio flow on CI's fresh n8n service."""

import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener
from uuid import uuid4


def request(opener, url, path, *, data=None, key=None):
    headers = {"Accept": "application/json"}
    if key is not None:
        headers["X-N8N-API-KEY"] = key
    body = None if data is None else json.dumps(data).encode()
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        with opener.open(Request(url + path, body, headers), timeout=10) as response:
            return json.load(response)
    except HTTPError as error:
        # Response bodies can include fixture credentials.
        raise AssertionError(f"n8n {path} returned HTTP {error.code}") from None


def check_cli(command, env, key):
    for args, field, expected in (
        (["doctor", "--no-secret-output"], "healthy", True),
        (["capabilities"], "status", "success"),
    ):
        result = subprocess.run(
            [*command, *args, "--format", "json"], env=env, capture_output=True,
            text=True, timeout=30,
        )
        output = result.stdout + result.stderr
        assert key not in output, f"{args[0]} exposed the fixture API key"
        report = json.loads(result.stdout)
        if args[0] == "doctor" and result.returncode:
            statuses = [(c["name"], c["status"]) for c in report["checks"]]
            raise AssertionError(f"doctor exited {result.returncode}: {statuses}")
        assert result.returncode == 0 and report[field] == expected, (
            f"{args[0]} failed: exit={result.returncode}, {field}={report[field]}"
        )
        print(f"{args[0]}: {field}={expected}", flush=True)


def check_approval(command, env, read_workflow, workflow_id, node_id):
    with subprocess.Popen(
        [*command, "mcp"], env=env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        encoding="utf-8", bufsize=1,
    ) as mcp:
        next_id = 0

        def rpc(method, params, notification=False):
            nonlocal next_id
            next_id += 1
            message = {"jsonrpc": "2.0", "method": method, "params": params}
            if not notification:
                message["id"] = next_id
            mcp.stdin.write(json.dumps(message) + "\n")
            mcp.stdin.flush()
            if notification:
                return
            line = mcp.stdout.readline()
            assert line, f"MCP closed stdout during {method}"
            reply = json.loads(line)
            assert reply.get("id") == next_id and "result" in reply, f"MCP {method} failed"
            return reply["result"]

        def tool(name, arguments):
            result = rpc("tools/call", {"name": name, "arguments": arguments})
            assert not result.get("isError"), f"MCP tool {name} rejected the call"
            return json.loads(result["content"][0]["text"])

        def expect_status(result, status):
            assert result["status"] == status, (
                f"{result['action']}: expected {status}, received {result['status']}"
            )

        def persisted_workflow(name):
            workflow = read_workflow()
            assert workflow["active"] is False, "Fixture workflow is active"
            assert [(node["id"], node["name"]) for node in workflow["nodes"]] == [
                (node_id, name)
            ], f"Unexpected stored workflow nodes after expecting {name}"
            return workflow

        try:
            rpc("initialize", {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "live-n8n-ci", "version": "1"},
            })
            rpc("notifications/initialized", {}, notification=True)

            old_name, new_name = "Manual Trigger", "Approved Trigger"
            original = persisted_workflow(old_name)
            mutation = {
                "workflowId": workflow_id,
                "operations": [{"op": "rename_node", "old_name": old_name, "new_name": new_name}],
            }
            preview = tool("n8n_mutate_nodes", {**mutation, "mode": "preview"})
            expect_status(preview, "preview")
            plan = preview["data"]
            modified = plan["mutationPlan"]["workflowDiff"]["modifiedNodes"]
            assert [(node["id"], node["beforeName"], node["afterName"]) for node in modified] == [
                (node_id, old_name, new_name)
            ], "Preview did not describe the proposed node rename"
            assert persisted_workflow(old_name)["versionId"] == original["versionId"]
            print(f"Preview proposed {old_name} -> {new_name}; stored version stayed unchanged.", flush=True)

            apply = {**mutation, "mode": "apply", "expectedVersionHash": plan["expectedVersionHash"]}
            blocked = tool("n8n_mutate_nodes", apply)
            expect_status(blocked, "blocked")
            assert blocked["data"]["errorCode"] == "POLICY_BLOCKED"
            assert "ApprovalReceipt" in blocked["data"]["message"], "Apply failed for a reason other than approval"
            assert persisted_workflow(old_name)["versionId"] == original["versionId"]
            print("Apply without approval was blocked; stored version stayed unchanged.", flush=True)

            # The CI client represents the operator approving this one fixture plan.
            confirmed = tool("n8n_workflows", {"action": "confirm_plan", "planId": plan["planId"]})
            expect_status(confirmed, "success")
            apply["approvalReceipt"] = confirmed["data"]["approvalReceipt"]
            applied = tool("n8n_mutate_nodes", apply)
            expect_status(applied, "success")
            assert applied["changed"] is True
            updated = persisted_workflow(new_name)
            assert updated["versionId"] != original["versionId"]
            expect_status(tool("n8n_mutate_nodes", apply), "blocked")
            assert persisted_workflow(new_name)["versionId"] == updated["versionId"]
            print("Approved rename persisted on the inactive workflow; approval replay was blocked.", flush=True)
        finally:
            mcp.stdin.close()
            if mcp.poll() is None:
                mcp.terminate()


def main():
    binary = Path(sys.argv[1]).resolve(strict=True)
    url = "http://127.0.0.1:5678"
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(http.cookiejar.CookieJar()))
    request(opener, url, "/rest/owner/setup", data={
        "email": "fixture@example.invalid", "firstName": "CI", "lastName": "Fixture",
        "password": "Aa1!" + secrets.token_urlsafe(24),
    })
    key = request(opener, url, "/rest/api-keys", data={
        "label": "Disposable CI fixture", "expiresAt": None,
        "scopes": ["workflow:list", "workflow:read", "workflow:create", "workflow:update"],
    })["data"]["rawApiKey"]
    node_id = str(uuid4())
    workflow = request(opener, url, "/api/v1/workflows", key=key, data={
        "name": "Approval fixture",
        "nodes": [{
            "id": node_id, "name": "Manual Trigger", "type": "n8n-nodes-base.manualTrigger",
            "typeVersion": 1, "position": [0, 0], "parameters": {},
        }],
        "connections": {}, "settings": {"executionOrder": "v1"},
    })
    workflow_id = workflow["id"]

    def read_workflow():
        return request(opener, url, f"/api/v1/workflows/{workflow_id}", key=key)

    catalog = Path("data/catalog.sqlite.zst").resolve(strict=True)
    with TemporaryDirectory(prefix="n8n-approval-") as directory:
        root = Path(directory)
        config = root / "instances.toml"
        config.write_text(
            f'[instances.fixture]\nurl = "{url}"\nenvironment = "development"\n'
            'policy = "production-guarded"\nallow_loopback_http = true\n'
            'api_key_env = "N8N_CI_FIXTURE_API_KEY"\n',
            encoding="utf-8",
        )
        env = {name: value for name, value in os.environ.items() if not name.startswith("N8N_")}
        env.update(N8N_CI_FIXTURE_API_KEY=key, RUST_BACKTRACE="0")
        command = [
            str(binary), "--instances-config", str(config), "--catalog-path", str(catalog),
            "--state-dir", str(root / "vault"),
        ]
        check_cli(command, env, key)
        check_approval(command, env, read_workflow, workflow_id, node_id)


if __name__ == "__main__":
    main()
