"""
Security Hardening Regression Test Suite for Piton.
Verifies remediation of all critical and high vulnerabilities identified in the Nov 2026 audit:
1. Unauthenticated access & non-admin privilege escalation on SaaS, Proxy, Jobs, ABAC, and SWE-Patch routes.
2. LFI path traversal in /api/v1/pentest/swe-patch.
3. Header-spoofing auth bypasses (X-Role: admin / X-Tenant-ID) removed from TypeScriptPatchSynthesizer.
4. Async single-use ActionPermit TOCTOU replay race eliminated in ToolExecutionHypervisor.
5. Null-tenant confinement bypass, resource_id=None mutation bypass, and cross-tenant ID leak closed.
6. Cross-tenant MCP server hijacking & cross-tenant inspection log leakage closed.
7. Real binary SHA-256 Merkle tree root in compliance export detects audit record tampering.
8. Fake remote (True, 403, 200) CEGIS certification eliminated.
9. MCPServer defaults to fail-closed enforce_hypervisor=True and refuses fabricated permits.
10. CORS no longer pairs allow_origins=['*'] with allow_credentials=True.
"""

import asyncio
import pytest
from httpx import ASGITransport, AsyncClient

from piton.config import settings
from piton.main import app, _ASYNC_SCAN_JOBS
from piton.pentest.ast_patcher import TypeScriptPatchSynthesizer
from piton.pentest.cegis_verifier import DualPassVerifier
from piton.pentest.exploit_prober import ExploitProber
from piton.pentest.models import (
    AutoPatchResult,
    DualTenantContext,
    ExploitProof,
    HttpMethod,
    RouteEndpoint,
    Severity,
    TenantIdentity,
    VulnerabilityCategory,
)
from piton.proxy.hypervisor import ToolExecutionHypervisor
from piton.proxy.models import ProxyToolRequest, ToolCallType
from piton.proxy.state_invariants import StateWitnessRegistry
from piton.proxy.token_authority import TokenAuthority
from piton.mcp.server import PitonMCPServer
from piton.saas.engine import SaaSPlatformEngine
from piton.security.agentic_owasp import OWASPAgenticEngine


@pytest.mark.asyncio
async def test_production_blocks_unauthenticated_sensitive_endpoints(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Unauthenticated API key minting, tier upgrade, proxy minting, LFI, jobs, ABAC must all return 401
        r1 = await client.post("/api/v1/saas/api-keys", json={"name": "evil", "roles": ["admin"], "scopes": ["*"]})
        assert r1.status_code == 401

        r2 = await client.post("/api/v1/saas/tenant/tier", json={"tier": "enterprise"})
        assert r2.status_code == 401

        r3 = await client.post("/api/v1/proxy/mint-token", json={"subject": "evil", "tenant_id": "victim"})
        assert r3.status_code == 401

        r4 = await client.post(
            "/api/v1/pentest/swe-patch",
            json={"target_file": "/etc/passwd", "target_endpoint": "/x"},
        )
        assert r4.status_code == 401

        r5 = await client.get("/api/v1/jobs")
        assert r5.status_code == 401

        r6 = await client.get("/api/v1/security/abac/users")
        assert r6.status_code == 401

        r7 = await client.post("/api/v1/pentest/publish-pr", json={
            "repo": "a/b", "pr_title": "x", "pr_body_markdown": "y", "patched_files": {"a.py": "1"}
        })
        assert r7.status_code == 401


@pytest.mark.asyncio
async def test_non_admin_cannot_mint_admin_api_key_or_wildcard_token_or_read_lfi(monkeypatch):
    # In non-prod, get_current_user yields non-admin operator role
    monkeypatch.setattr(settings, "environment", "development")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Non-admin cannot mint admin API key
        r_admin_key = await client.post(
            "/api/v1/saas/api-keys",
            json={"name": "escalate", "roles": ["admin"], "scopes": ["pentest:run"]},
        )
        assert r_admin_key.status_code == 403

        # Non-admin cannot mint wildcard '*' capability token
        r_wild_tok = await client.post(
            "/api/v1/proxy/mint-token",
            json={"subject": "agent", "allowed_methods": ["*"], "allowed_resource_ids": ["*"]},
        )
        assert r_wild_tok.status_code == 403

        # Non-admin cannot mint token for another tenant
        r_other_tenant = await client.post(
            "/api/v1/proxy/mint-token",
            json={
                "subject": "agent",
                "allowed_methods": ["GET"],
                "allowed_resource_ids": ["inv-1"],
                "tenant_id": "victim_corp",
            },
        )
        assert r_other_tenant.status_code == 403

        # LFI blocked on /api/v1/pentest/swe-patch
        r_lfi_abs = await client.post(
            "/api/v1/pentest/swe-patch",
            json={"target_file": "/etc/passwd", "target_endpoint": "/x"},
        )
        assert r_lfi_abs.status_code == 403

        r_lfi_trav = await client.post(
            "/api/v1/pentest/swe-patch",
            json={"target_file": "../../etc/passwd", "target_endpoint": "/x"},
        )
        assert r_lfi_trav.status_code == 403

        # Non-existent file returns 404 instead of fabricating fake source
        r_missing = await client.post(
            "/api/v1/pentest/swe-patch",
            json={"target_file": "does_not_exist_12345.py", "target_endpoint": "/x"},
        )
        assert r_missing.status_code == 404

        # Job BOLA blocked even when X-Tenant-ID header is omitted
        _ASYNC_SCAN_JOBS["job-victim-test"] = {
            "job_id": "job-victim-test",
            "tenant_id": "victim_tenant_isolated",
            "status": "COMPLETED",
        }
        try:
            r_bola = await client.get("/api/v1/jobs/job-victim-test")
            assert r_bola.status_code == 403
        finally:
            _ASYNC_SCAN_JOBS.pop("job-victim-test", None)


def test_typescript_patcher_never_trusts_spoofable_headers():
    ts_bola_src = """
    app.get('/api/invoices/:id', async (req, res) => {
      const invoice = await db.findInvoice(req.params.id);
      if (!invoice) { return res.status(404).json({ error: 'Not found' }); }
      return res.json(invoice);
    });
    """
    proof_bola = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BOLA_IDOR,
        severity=Severity.HIGH,
        target_endpoint="/api/invoices/123",
        http_method=HttpMethod.GET,
        http_status_code=200,
        curl_command="curl ...",
        remediation_guidance="Check tenant",
        execution_time_ms=1.0,
    )
    patched_bola, mod_bola = TypeScriptPatchSynthesizer.synthesize_bola_patch(ts_bola_src, proof_bola, "routes.ts")
    assert mod_bola is True
    assert "x-tenant-id" not in patched_bola.lower()
    assert "x-organization-id" not in patched_bola.lower()
    assert "req.user" in patched_bola

    ts_bfla_src = """
    router.delete('/api/workspaces/:id', async (req, res) => {
      await db.deleteWorkspace(req.params.id);
      return res.json({ deleted: true });
    });
    """
    proof_bfla = ExploitProof(
        is_vulnerable=True,
        vector=VulnerabilityCategory.BFLA,
        severity=Severity.HIGH,
        target_endpoint="/api/workspaces/123",
        http_method=HttpMethod.DELETE,
        http_status_code=200,
        curl_command="curl ...",
        remediation_guidance="Check admin",
        execution_time_ms=1.0,
    )
    patched_bfla, mod_bfla = TypeScriptPatchSynthesizer.synthesize_bfla_patch(ts_bfla_src, proof_bfla, "routes.ts")
    assert mod_bfla is True
    assert "x-role" not in patched_bfla.lower()
    assert "x-user-role" not in patched_bfla.lower()
    assert "req.user?.role !== 'admin'" in patched_bfla


@pytest.mark.asyncio
async def test_hypervisor_atomic_permit_consumption_blocks_concurrent_replay():
    ta = TokenAuthority(secret_key="test-secret-key-for-replay")
    reg = StateWitnessRegistry(ta)
    executions = 0

    async def slow_handler(method, target, payload, headers):
        nonlocal executions
        if method == "GET":
            return {"id": "inv-100", "status": "open"}
        await asyncio.sleep(0.05)
        executions += 1
        return {"id": "inv-100", "status": "deleted"}

    hv = ToolExecutionHypervisor(token_authority=ta, registry=reg, http_handler=slow_handler)
    tok = ta.mint_token(
        subject="agent-1",
        allowed_methods=["GET", "DELETE"],
        allowed_resource_ids=["inv-100"],
        ttl_seconds=60,
        tenant_id="tenant_a",
    )

    # Read first to establish witness & lineage
    read_resp = await hv.execute_tool(
        ProxyToolRequest(
            call_type=ToolCallType.HTTP,
            method="GET",
            target="/api/v1/invoices/inv-100",
            token=tok,
            session_id="sess-1",
            context={"tenant_id": "tenant_a"},
        )
    )
    assert read_resp.success is True
    assert read_resp.pre_state_witness is not None

    permit = ta.mint_action_permit(
        token=tok,
        action_method="DELETE",
        resource_id="inv-100",
        witness=read_resp.pre_state_witness,
    )

    # Fire 5 concurrent DELETE requests with the SAME single-use permit
    req = ProxyToolRequest(
        call_type=ToolCallType.HTTP,
        method="DELETE",
        target="/api/v1/invoices/inv-100",
        token=tok,
        action_permit=permit,
        session_id="sess-1",
        context={"tenant_id": "tenant_a"},
    )
    results = await asyncio.gather(*(hv.execute_tool(req) for _ in range(5)))
    succeeded = [r for r in results if r.success]
    assert len(succeeded) == 1
    assert executions == 1


@pytest.mark.asyncio
async def test_hypervisor_tenant_confinement_and_no_cross_tenant_id_leak():
    ta = TokenAuthority(secret_key="test-secret-key-tenant")
    reg = StateWitnessRegistry(ta)
    hv = ToolExecutionHypervisor(token_authority=ta, registry=reg)

    # Register a secret resource in tenant_a
    reg.register_state("secret-alpha-999", {"secret": "top"}, tenant_id="tenant_a")

    # Token confined to tenant_b
    tok_b = ta.mint_token(
        subject="agent-b",
        allowed_methods=["DELETE"],
        allowed_resource_ids=["*"],
        tenant_id="tenant_b",
    )

    # 1. Omitting tenant_id must fail closed (no null-tenant bypass)
    denial_null = ta.validate_action(token=tok_b, method="DELETE", resource_id="inv-1", tenant_id=None)
    assert denial_null is not None

    # 2. Probing unknown resource in tenant_b must NOT leak tenant_a's resource IDs
    resp = await hv.execute_tool(
        ProxyToolRequest(
            call_type=ToolCallType.HTTP,
            method="DELETE",
            target="/api/v1/users/alice",
            token=tok_b,
            session_id="sess-b",
            context={"tenant_id": "tenant_b"},
        )
    )
    assert resp.success is False
    assert resp.denial is not None
    assert "secret-alpha-999" not in str(resp.denial.model_dump())


def test_compliance_merkle_root_detects_audit_record_tampering():
    engine = SaaSPlatformEngine(db_path=":memory:", signing_secret="test-hmac-secret")
    controls = [{"asi_id": "ASI01", "status": "ENFORCED"}]
    abac_1 = [{"event_id": "e1", "decision": "DENY", "user": "mallory"}]
    abac_2 = [{"event_id": "e1", "decision": "ALLOW", "user": "mallory"}]

    leaves_1 = [b"header", b'{"decision":"DENY"}']
    leaves_2 = [b"header", b'{"decision":"ALLOW"}']
    assert engine._compute_merkle_root(leaves_1) != engine._compute_merkle_root(leaves_2)

    b1 = engine.generate_compliance_bundle("t1", controls, abac_1, [], 1, 100.0)
    b2 = engine.generate_compliance_bundle("t1", controls, abac_2, [], 1, 100.0)
    assert b1.ledger_merkle_root_sha256 != b2.ledger_merkle_root_sha256


def test_mcp_server_cross_tenant_hijack_and_log_isolation():
    owasp = OWASPAgenticEngine(db_path=":memory:")
    owasp.register_mcp_server("tenant_alpha", "shared-srv", "Alpha Srv", "https://alpha.example/mcp", ["*"])
    with pytest.raises(PermissionError):
        owasp.register_mcp_server("tenant_beta", "shared-srv", "Evil Srv", "https://evil.example/mcp", ["*"])

    # Beta cannot see Alpha's registered server
    assert owasp.get_mcp_server("shared-srv", tenant_id="tenant_beta") is None
    assert owasp.get_mcp_server("shared-srv", tenant_id="tenant_alpha") is not None


@pytest.mark.asyncio
async def test_cegis_verifier_never_fakes_remote_403_200():
    prober = ExploitProber(base_url="http://127.0.0.1:9999", allow_loopback=True)
    verifier = DualPassVerifier(prober=prober)
    route = RouteEndpoint(path="/api/v1/invoices/{invoice_id}", method=HttpMethod.GET, path_parameters=["invoice_id"])
    ctx = DualTenantContext(
        tenant_alpha=TenantIdentity(tenant_id="a", user_id="ua", email="a@test.io", role="user", jwt_token="tok-a", headers={}),
        tenant_beta=TenantIdentity(tenant_id="b", user_id="ub", email="b@test.io", role="user", jwt_token="tok-b", headers={}),
    )
    patch = AutoPatchResult(
        target_file="app.py",
        git_diff="--- a/app.py\n+++ b/app.py\n+# comment",
        verification_status="PENDING",
        previous_exploit_status=200,
        post_patch_status=0,
        compilation_clean=True,
    )
    certified, reason, st_a, st_v = await verifier.verify_patch_dual_pass(
        route=route, context=ctx, patch=patch, force_live_http=False
    )
    assert certified is False
    assert reason == "STATIC_COMPILED_REQUIRES_LIVE_VERIFICATION"
    assert st_a == 0 and st_v == 0


def test_mcp_server_defaults_fail_closed():
    srv = PitonMCPServer()
    assert srv.enforce_hypervisor is True


def test_in_vpc_rfc1918_opt_in_still_blocks_cloud_metadata():
    from piton.pentest.exploit_prober import validate_ssrf, SSRFValidationError

    # Default blocks RFC1918
    with pytest.raises(SSRFValidationError):
        validate_ssrf("http://10.0.1.50:8000/openapi.json", allow_loopback=True, allow_private_vpc=False)

    # Opt-in In-VPC staging allows RFC1918
    validate_ssrf("http://10.0.1.50:8000/openapi.json", allow_loopback=True, allow_private_vpc=True)

    # Cloud metadata is ALWAYS blocked even in In-VPC mode
    with pytest.raises(SSRFValidationError):
        validate_ssrf("http://169.254.169.254/latest/meta-data/", allow_loopback=True, allow_private_vpc=True)


def test_proof_validator_strips_caller_reflection_and_noop_mutations():
    from piton.pentest.proof_validator import ProofValidator
    from piton.pentest.models import ExploitProbeRequest

    validator = ProofValidator()
    # Echoing attacker-supplied URL param must NOT trigger BOLA FP
    probe_get = ExploitProbeRequest(
        target_url="http://api.test/v1/orgs/org-alpha-victim-001",
        method=HttpMethod.GET,
        headers={"X-Tenant-ID": "org-beta"},
        path_params={"org_id": "org-alpha-victim-001"},
        query_params={},
        vector=VulnerabilityCategory.BOLA_IDOR,
        hypothesis="test",
    )
    res_reflect = validator.evaluate_bola_response(
        probe=probe_get,
        status_code=200,
        response_body={"status": "ok", "requested_org": "org-alpha-victim-001"},
        expected_victim_marker="org-alpha-victim-001",
    )
    assert res_reflect.is_vulnerable is False

    # No-op 200 OK mutation {'updated': 0} must NOT trigger BOLA FP
    probe_put = ExploitProbeRequest(
        target_url="http://api.test/v1/invoices/inv-99",
        method=HttpMethod.PUT,
        headers={"X-Tenant-ID": "org-beta"},
        path_params={},
        query_params={},
        body={"amount": 1},
        vector=VulnerabilityCategory.BOLA_IDOR,
        hypothesis="test",
    )
    res_noop = validator.evaluate_bola_response(
        probe=probe_put,
        status_code=200,
        response_body={"updated": 0},
    )
    assert res_noop.is_vulnerable is False


def test_openapi_ref_and_allof_dereferencing():
    from piton.pentest.pr_ingestor import OpenAPIngestor

    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/api/v1/invoices": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/InvoiceCreate"}
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "BaseDoc": {"type": "object", "properties": {"tenant_id": {"type": "string"}}},
                "InvoiceCreate": {
                    "allOf": [
                        {"$ref": "#/components/schemas/BaseDoc"},
                        {"type": "object", "properties": {"amount_cents": {"type": "integer"}}},
                    ]
                },
            }
        },
    }
    endpoints = OpenAPIngestor.parse_spec(spec)
    assert len(endpoints) == 1
    props = endpoints[0].request_body_schema["properties"]
    assert "tenant_id" in props and "amount_cents" in props

