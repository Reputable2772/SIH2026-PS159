"""
SecureMailScope — Dynamic OpenAPI Documentation Engine
Dynamically generates interactive HTML documentation and tool-friendly JSON shape catalogs
directly from FastAPI's live OpenAPI schema (derived from Python docstrings and Pydantic models).
"""

from __future__ import annotations

import json
from typing import Any


def resolve_schema_name(schema: dict[str, Any] | None) -> str:
    """Extract a human-friendly model/type name from an OpenAPI schema object."""
    if not schema:
        return "void"
    if "$ref" in schema:
        return schema["$ref"].split("/")[-1]
    if schema.get("type") == "array" and "items" in schema:
        item_name = resolve_schema_name(schema["items"])
        return f"list[{item_name}]"
    if "anyOf" in schema:
        return " | ".join(resolve_schema_name(s) for s in schema["anyOf"])
    return schema.get("type", "object")


def resolve_schema_shape(
    schema: dict[str, Any] | None,
    schemas: dict[str, Any],
    depth: int = 0,
) -> Any:
    """Recursively resolves an OpenAPI schema into a clean, concrete JSON shape description."""
    if not schema or depth > 3:
        return "any"

    if "$ref" in schema:
        ref_name = schema["$ref"].split("/")[-1]
        if ref_name in schemas:
            target = schemas[ref_name]
            return resolve_schema_shape(target, schemas, depth + 1)
        return ref_name

    if "anyOf" in schema:
        return " | ".join(resolve_schema_name(s) for s in schema["anyOf"])

    s_type = schema.get("type")
    if s_type == "array":
        item_shape = resolve_schema_shape(schema.get("items"), schemas, depth + 1)
        return [item_shape]

    if "properties" in schema:
        res = {}
        for p_name, p_info in schema["properties"].items():
            p_type = p_info.get("type")
            p_desc = p_info.get("description", "")
            if "$ref" in p_info:
                ref_sub = p_info["$ref"].split("/")[-1]
                res[p_name] = f"<{ref_sub}>"
            elif p_type == "array":
                sub_items = p_info.get("items", {})
                if "$ref" in sub_items:
                    res[p_name] = [f"<{sub_items['$ref'].split('/')[-1]}>"]
                else:
                    res[p_name] = [sub_items.get("type", "any")]
            else:
                desc_hint = f" ({p_desc})" if p_desc else ""
                res[p_name] = f"{p_type or 'any'}{desc_hint}"
        return res

    return s_type or "object"


def generate_curl_command(
    method: str,
    path: str,
    parameters: list[dict[str, Any]],
    request_body: dict[str, Any] | None,
) -> str:
    """Synthesizes a realistic curl command from path and OpenAPI metadata."""
    sample_path = path
    # Replace path parameters with realistic sample values
    replacements = {
        "{filename}": "01_enterprise_secure_baseline.pcap",
        "{analysis_id}": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "{session_id}": "stream-0",
    }
    for k, v in replacements.items():
        sample_path = sample_path.replace(k, v)

    query_params = [p for p in parameters if p.get("in") == "query" and p.get("required")]
    if query_params:
        q_str = "&".join(f"{p['name']}={p.get('example', 'value')}" for p in query_params)
        sample_path = f"{sample_path}?{q_str}"

    base_url = "http://localhost:8000"
    if method == "GET":
        return f"curl -s {base_url}{sample_path}"
    elif method == "POST":
        if request_body:
            ct = request_body.get("content_type", "application/json")
            if "multipart" in ct:
                return f"curl -X POST -F 'file=@sample.pcap' {base_url}{sample_path}"
            example = request_body.get("example")
            if example:
                body_json = json.dumps(example)
                return f"curl -X POST {base_url}{sample_path} -H 'Content-Type: application/json' -d '{body_json}'"
        return f"curl -X POST {base_url}{sample_path}"

    return f"curl -X {method} {base_url}{sample_path}"


def get_api_catalog(openapi: dict[str, Any]) -> dict[str, Any]:
    """
    Dynamically extracts a structured catalog of endpoints and shapes
    from FastAPI's live openapi schema for automated tools and coding agents.
    """
    schemas = openapi.get("components", {}).get("schemas", {})
    endpoints = []

    for path, methods in openapi.get("paths", {}).items():
        for method_name, op in methods.items():
            if method_name.lower() not in (
                "get",
                "post",
                "put",
                "delete",
                "patch",
            ):
                continue

            # Extract response model
            resps = op.get("responses", {})
            resp_200 = resps.get("200") or resps.get(200) or {}
            content = resp_200.get("content", {})
            ct = next(iter(content.keys()), "application/json") if content else "application/json"
            resp_schema = content.get(ct, {}).get("schema") if content else None
            model_name = resolve_schema_name(resp_schema)
            shape = resolve_schema_shape(resp_schema, schemas)

            # Request body
            req_body_obj = op.get("requestBody")
            req_body = None
            if req_body_obj:
                rb_content = req_body_obj.get("content", {})
                rb_ct = (
                    next(iter(rb_content.keys()), "application/json")
                    if rb_content
                    else "application/json"
                )
                rb_schema = rb_content.get(rb_ct, {}).get("schema", {})
                req_body = {
                    "content_type": rb_ct,
                    "model": resolve_schema_name(rb_schema),
                    "schema": rb_schema,
                    "shape": resolve_schema_shape(rb_schema, schemas),
                }

            # Parameters
            params = [
                {
                    "name": p.get("name"),
                    "in": p.get("in"),
                    "required": p.get("required", False),
                    "type": p.get("schema", {}).get("type", "string"),
                    "description": p.get("description", ""),
                    "example": p.get("example") or p.get("schema", {}).get("example"),
                }
                for p in op.get("parameters", [])
            ]

            curl_cmd = generate_curl_command(method_name.upper(), path, params, req_body)

            endpoints.append(
                {
                    "id": op.get(
                        "operationId",
                        f"{method_name}_{path.replace('/', '_')}",
                    ),
                    "group": (op.get("tags") or ["General"])[0],
                    "method": method_name.upper(),
                    "path": path,
                    "summary": op.get("summary", ""),
                    "description": op.get("description", "").strip(),
                    "parameters": params,
                    "request_body": req_body,
                    "response": {
                        "status_code": 200,
                        "content_type": ct,
                        "model": model_name,
                        "shape": shape,
                    },
                    "curl_example": curl_cmd,
                }
            )

    return {
        "api": openapi.get("info", {}).get("title", "SecureMailScope API"),
        "version": openapi.get("info", {}).get("version", "0.1.0"),
        "description": openapi.get("info", {}).get("description", ""),
        "base_url": "/",
        "openapi_url": "/openapi.json",
        "documentation_url": "/docs",
        "endpoints": endpoints,
        "models": schemas,
    }


def render_docs_html(openapi: dict[str, Any]) -> str:
    """Renders a self-contained, aesthetic, dark-mode interactive HTML API reference dynamically from OpenAPI."""
    catalog = get_api_catalog(openapi)
    endpoints = catalog.get("endpoints", [])
    models = catalog.get("models", {})

    # Group endpoints by group (tag)
    groups: dict[str, list[dict[str, Any]]] = {}
    for ep in endpoints:
        grp = ep.get("group", "General")
        groups.setdefault(grp, []).append(ep)

    nav_links_html = []
    content_html = []

    for grp, eps in groups.items():
        nav_links_html.append(f'<div class="nav-group-title">{grp}</div>')
        for ep in eps:
            ep_id = ep["id"]
            method = ep["method"]
            path = ep["path"]
            nav_links_html.append(
                f'<a href="#{ep_id}" class="nav-item">'
                f'<span class="badge badge-{method.lower()}">{method}</span>'
                f'<span class="nav-path">{path}</span>'
                f"</a>"
            )

            # Build endpoint section
            params = ep.get("parameters", [])
            params_html = ""
            if params:
                params_rows = "".join(
                    f"<tr>"
                    f"<td><code>{p['name']}</code></td>"
                    f'<td><span class="type-tag">{p.get("type", "string")}</span></td>'
                    f'<td><span class="badge badge-{"req" if p.get("required") else "opt"}">{"Required" if p.get("required") else "Optional"}</span></td>'
                    f"<td>{p.get('description', '')}</td>"
                    f"</tr>"
                    for p in params
                )
                params_html = f"""
                <div class="section-block">
                    <div class="section-label">Parameters</div>
                    <table class="spec-table">
                        <thead><tr><th>Name</th><th>Type</th><th>Requirement</th><th>Description</th></tr></thead>
                        <tbody>{params_rows}</tbody>
                    </table>
                </div>
                """

            # Request Body
            req_body = ep.get("request_body")
            req_body_html = ""
            if req_body:
                ct = req_body.get("content_type", "application/json")
                shape_str = json.dumps(req_body.get("shape", req_body.get("schema", {})), indent=2)
                req_body_html = f"""
                <div class="section-block">
                    <div class="section-label">Request Body <span class="content-type">({ct})</span> <span class="model-tag">Model: {req_body.get("model")}</span></div>
                    <div class="code-sublabel">Payload Shape:</div>
                    <pre><code>{shape_str}</code></pre>
                </div>
                """

            # Response
            resp = ep.get("response", {})
            status_code = resp.get("status_code", 200)
            resp_ct = resp.get("content_type", "application/json")
            resp_model = resp.get("model", "Object")
            resp_shape = resp.get("shape", {})
            resp_shape_str = (
                json.dumps(resp_shape, indent=2)
                if isinstance(resp_shape, (dict, list))
                else str(resp_shape)
            )

            curl_cmd = ep.get("curl_example", f"curl http://localhost:8000{path}")

            content_html.append(
                f"""
                <article class="endpoint-card" id="{ep_id}">
                    <div class="endpoint-header">
                        <span class="badge badge-{method.lower()} method-lg">{method}</span>
                        <h3 class="endpoint-path">{path}</h3>
                        <span class="badge badge-status">HTTP {status_code}</span>
                    </div>
                    <div class="endpoint-summary">{ep.get("summary", "")}</div>
                    <p class="endpoint-desc">{ep.get("description", "")}</p>

                    {params_html}
                    {req_body_html}

                    <div class="section-block">
                        <div class="section-label">
                            Response Shape
                            <span class="content-type">({resp_ct})</span>
                            <span class="model-tag">Model: {resp_model}</span>
                        </div>
                        <div class="code-sublabel">Schema & Shape:</div>
                        <pre><code>{resp_shape_str}</code></pre>
                    </div>

                    <div class="section-block">
                        <div class="section-label">Curl Execution</div>
                        <div class="curl-box">
                            <pre><code>{curl_cmd}</code></pre>
                            <button class="copy-btn" onclick="copyText('{curl_cmd}')">Copy</button>
                        </div>
                    </div>
                </article>
                """
            )

    # Models section
    models_nav = '<div class="nav-group-title">Data Models & Schemas</div>'
    models_content = []
    for m_name, m_spec in sorted(models.items()):
        m_slug = f"model-{m_name.lower()}"
        models_nav += f'<a href="#{m_slug}" class="nav-item"><span class="badge badge-model">TYPE</span><span class="nav-path">{m_name}</span></a>'
        props = m_spec.get("properties", {})
        props_rows = "".join(
            f'<tr><td><code>{p_name}</code></td><td><span class="type-tag">{p_info.get("type", p_info.get("$ref", "any"))}</span></td><td>{p_info.get("description", "")}</td></tr>'
            for p_name, p_info in props.items()
        )
        models_content.append(
            f"""
            <article class="endpoint-card model-card" id="{m_slug}">
                <div class="endpoint-header">
                    <span class="badge badge-model method-lg">MODEL</span>
                    <h3 class="endpoint-path">{m_name}</h3>
                </div>
                <p class="endpoint-desc">{m_spec.get("description", "")}</p>
                <table class="spec-table">
                    <thead><tr><th>Property</th><th>Type</th><th>Description</th></tr></thead>
                    <tbody>{props_rows}</tbody>
                </table>
            </article>
            """
        )

    nav_links_joined = "\n".join(nav_links_html) + "\n" + models_nav
    endpoints_joined = "\n".join(content_html)
    models_joined = "\n".join(models_content)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMailScope API Documentation & Shape Reference</title>
    <style>
        :root {{
            --bg-canvas: #080c14;
            --bg-card: #0f172a;
            --bg-card-hover: #1e293b;
            --bg-code: #030712;
            --border-color: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-emerald: #10b981;
            --accent-amber: #f59e0b;
            --accent-rose: #f43f5e;
            --accent-violet: #8b5cf6;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", Helvetica, Arial, sans-serif;
            --font-mono: "JetBrains Mono", "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-canvas);
            color: var(--text-main);
            font-family: var(--font-sans);
            line-height: 1.6;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }}
        header {{
            background: #0b1120;
            border-bottom: 1px solid var(--border-color);
            position: sticky;
            top: 0;
            z-index: 100;
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .brand-logo {{
            width: 34px;
            height: 34px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            color: #030712;
            font-size: 1.1rem;
        }}
        .brand-title {{
            font-size: 1.15rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .brand-version {{
            font-size: 0.75rem;
            color: var(--accent-cyan);
            background: rgba(6, 182, 212, 0.1);
            border: 1px solid rgba(6, 182, 212, 0.25);
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            margin-left: 0.5rem;
            font-family: var(--font-mono);
        }}
        .header-actions {{
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }}
        .btn {{
            font-size: 0.85rem;
            font-weight: 500;
            padding: 0.45rem 0.85rem;
            border-radius: 6px;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
        }}
        .btn-outline {{
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-main);
            border: 1px solid var(--border-color);
        }}
        .btn-outline:hover {{
            background: rgba(255, 255, 255, 0.1);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }}

        .workspace {{
            display: flex;
            flex: 1;
        }}
        .sidebar {{
            width: 320px;
            background: #090e1a;
            border-right: 1px solid var(--border-color);
            position: sticky;
            top: 65px;
            height: calc(100vh - 65px);
            overflow-y: auto;
            padding: 1.5rem 1rem;
        }}
        .search-box {{
            margin-bottom: 1.25rem;
        }}
        .search-box input {{
            width: 100%;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-main);
            padding: 0.5rem 0.75rem;
            font-size: 0.85rem;
            outline: none;
        }}
        .search-box input:focus {{
            border-color: var(--accent-cyan);
        }}
        .nav-group-title {{
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-muted);
            font-weight: 700;
            margin: 1.25rem 0 0.5rem 0.25rem;
        }}
        .nav-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.4rem 0.5rem;
            border-radius: 6px;
            color: #cbd5e1;
            text-decoration: none;
            font-size: 0.82rem;
            transition: background 0.15s ease;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .nav-item:hover {{
            background: var(--bg-card-hover);
            color: #fff;
        }}
        .nav-path {{
            font-family: var(--font-mono);
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .content {{
            flex: 1;
            padding: 2.5rem 3.5rem;
            max-width: 1100px;
            overflow-y: auto;
        }}
        .overview-hero {{
            margin-bottom: 3rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
        }}
        .overview-hero h1 {{
            font-size: 2.1rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            margin-bottom: 0.75rem;
        }}
        .overview-hero p {{
            font-size: 1.05rem;
            color: var(--text-muted);
            max-width: 800px;
        }}
        .badge-bar {{
            display: flex;
            gap: 0.6rem;
            margin-top: 1.25rem;
            flex-wrap: wrap;
        }}
        .spec-pill {{
            font-size: 0.8rem;
            font-family: var(--font-mono);
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            padding: 0.25rem 0.65rem;
            border-radius: 9999px;
            color: #cbd5e1;
        }}

        .endpoint-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.75rem;
            margin-bottom: 2rem;
            scroll-margin-top: 90px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        }}
        .endpoint-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
        }}
        .endpoint-path {{
            font-family: var(--font-mono);
            font-size: 1.15rem;
            font-weight: 700;
            color: #f1f5f9;
        }}
        .endpoint-summary {{
            font-size: 1rem;
            font-weight: 600;
            color: #e2e8f0;
            margin-bottom: 0.35rem;
        }}
        .endpoint-desc {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 1.25rem;
        }}

        .badge {{
            font-family: var(--font-mono);
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .method-lg {{
            font-size: 0.85rem;
            padding: 0.3rem 0.65rem;
        }}
        .badge-get {{ background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-post {{ background: rgba(59, 130, 246, 0.15); color: var(--accent-blue); border: 1px solid rgba(59, 130, 246, 0.3); }}
        .badge-model {{ background: rgba(139, 92, 246, 0.15); color: var(--accent-violet); border: 1px solid rgba(139, 92, 246, 0.3); }}
        .badge-status {{ background: rgba(255, 255, 255, 0.05); color: #94a3b8; border: 1px solid var(--border-color); margin-left: auto; }}
        .badge-req {{ background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); border: 1px solid rgba(244, 63, 94, 0.3); }}
        .badge-opt {{ background: rgba(148, 163, 184, 0.1); color: var(--text-muted); border: 1px solid var(--border-color); }}
        .type-tag {{ font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan); }}
        .model-tag {{ font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-violet); margin-left: 0.5rem; }}

        .section-block {{
            margin-top: 1.25rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-color);
        }}
        .section-label {{
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #94a3b8;
            font-weight: 700;
            margin-bottom: 0.65rem;
            display: flex;
            align-items: center;
        }}
        .content-type {{
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: #64748b;
            margin-left: 0.5rem;
            text-transform: none;
        }}
        .code-sublabel {{
            font-size: 0.75rem;
            color: #64748b;
            font-weight: 600;
            margin: 0.6rem 0 0.25rem 0.2rem;
            font-family: var(--font-mono);
        }}
        .spec-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            margin-bottom: 0.75rem;
        }}
        .spec-table th, .spec-table td {{
            padding: 0.6rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        .spec-table th {{
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
        }}
        pre {{
            background: var(--bg-code);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.85rem 1rem;
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 0.82rem;
            color: #e2e8f0;
            margin-bottom: 0.75rem;
        }}
        code {{
            font-family: var(--font-mono);
        }}
        .curl-box {{
            position: relative;
        }}
        .curl-box pre {{
            margin-bottom: 0;
            padding-right: 5rem;
        }}
        .copy-btn {{
            position: absolute;
            top: 8px;
            right: 8px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--border-color);
            color: #cbd5e1;
            border-radius: 4px;
            padding: 0.25rem 0.6rem;
            font-size: 0.72rem;
            cursor: pointer;
            font-family: var(--font-mono);
            transition: all 0.2s ease;
        }}
        .copy-btn:hover {{
            background: var(--accent-cyan);
            color: #030712;
            border-color: var(--accent-cyan);
        }}

        #toast {{
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--accent-cyan);
            color: #030712;
            font-weight: 600;
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            font-size: 0.85rem;
            display: none;
            box-shadow: 0 4px 15px rgba(6, 182, 212, 0.4);
            z-index: 1000;
        }}
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <div class="brand-logo">SM</div>
            <div class="brand-title">SecureMailScope API<span class="brand-version">v0.1.0</span></div>
        </div>
        <div class="header-actions">
            <a href="/docs?format=json" class="btn btn-outline" target="_blank">Raw JSON Spec</a>
            <a href="/openapi.json" class="btn btn-outline" target="_blank">OpenAPI 3.1</a>
            <a href="/redoc" class="btn btn-outline" target="_blank">ReDoc</a>
            <a href="/api/health" class="btn btn-outline" target="_blank">Health</a>
        </div>
    </header>

    <div class="workspace">
        <aside class="sidebar">
            <div class="search-box">
                <input type="text" id="endpointSearch" placeholder="Filter endpoints & models..." onkeyup="filterEndpoints()">
            </div>
            <nav id="sidebarNav">
                {nav_links_joined}
            </nav>
        </aside>

        <main class="content">
            <section class="overview-hero">
                <h1>Forensic API Reference & Shape Catalog</h1>
                <p>
                    Interactive specifications and data contract shapes for tools, AI agents, and security automation
                    consuming the SecureMailScope passive network forensic service.
                </p>
                <div class="badge-bar">
                    <span class="spec-pill">RFC 5321 (SMTP)</span>
                    <span class="spec-pill">RFC 3501 (IMAP)</span>
                    <span class="spec-pill">RFC 1939 (POP3)</span>
                    <span class="spec-pill">RFC 8446 (TLS 1.3)</span>
                    <span class="spec-pill">Isolation Forest (16-D ML)</span>
                    <span class="spec-pill">ReportLab Forensic PDF</span>
                </div>
            </section>

            <section id="endpointsList">
                {endpoints_joined}
            </section>

            <section id="modelsList">
                <div class="overview-hero" style="margin-top: 4rem;">
                    <h1>Core Data Models & Pydantic Schemas</h1>
                    <p>Internal type definitions flowing through forensic state machines and analysis pipelines.</p>
                </div>
                {models_joined}
            </section>
        </main>
    </div>

    <div id="toast">Copied to clipboard!</div>

    <script>
        function copyText(txt) {{
            navigator.clipboard.writeText(txt).then(() => {{
                const toast = document.getElementById('toast');
                toast.style.display = 'block';
                setTimeout(() => {{ toast.style.display = 'none'; }}, 2000);
            }});
        }}

        function filterEndpoints() {{
            const val = document.getElementById('endpointSearch').value.toLowerCase();
            const items = document.querySelectorAll('.nav-item');
            const cards = document.querySelectorAll('.endpoint-card');

            items.forEach(el => {{
                const match = el.textContent.toLowerCase().includes(val);
                el.style.display = match ? 'flex' : 'none';
            }});

            cards.forEach(card => {{
                const match = card.textContent.toLowerCase().includes(val);
                card.style.display = match ? 'block' : 'none';
            }});
        }}
    </script>
</body>
</html>"""
