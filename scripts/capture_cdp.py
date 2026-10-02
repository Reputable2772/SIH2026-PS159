import asyncio
import base64
import json
import sys
import urllib.request

import websockets


async def capture(
    url: str, output_path: str, wait_seconds: float = 2.0, click_selector: str | None = None
):
    # Find page target
    req = urllib.request.urlopen("http://localhost:9222/json")
    targets = json.loads(req.read().decode())
    page_target = next(
        t for t in targets if t.get("type") == "page" and "localhost:5173" in t.get("url", "")
    )
    ws_url = page_target["webSocketDebuggerUrl"]

    async with websockets.connect(ws_url, max_size=20 * 1024 * 1024) as ws:
        msg_id = 1

        async def send(method, params=None):
            nonlocal msg_id
            m = {"id": msg_id, "method": method, "params": params or {}}
            msg_id += 1
            await ws.send(json.dumps(m))
            while True:
                resp = json.loads(await ws.recv())
                if resp.get("id") == m["id"]:
                    return resp.get("result", {})

        # Resize viewport to 1440x960
        await send(
            "Emulation.setDeviceMetricsOverride",
            {"width": 1440, "height": 960, "deviceScaleFactor": 1, "mobile": False},
        )

        # Navigate
        print(f"Navigating to {url}...")
        await send("Page.navigate", {"url": url})
        await asyncio.sleep(wait_seconds)

        if click_selector:
            # Click selector via Runtime.evaluate
            eval_js = f"""
            (() => {{
                const el = document.querySelector('{click_selector}');
                if (el) {{ el.click(); return true; }}
                // Try finding by text
                const buttons = Array.from(document.querySelectorAll('button'));
                const btn = buttons.find(b => b.textContent.includes('{click_selector}'));
                if (btn) {{ btn.click(); return true; }}
                return false;
            }})()
            """
            res = await send("Runtime.evaluate", {"expression": eval_js})
            print(f"Clicked {click_selector}: {res}")
            await asyncio.sleep(1.0)

        # Capture screenshot
        result = await send("Page.captureScreenshot", {"format": "png"})
        img_bytes = base64.b64decode(result["data"])
        with open(output_path, "wb") as f:
            f.write(img_bytes)
        print(f"Saved screenshot ({len(img_bytes)} bytes) to {output_path}")


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5173/"
    out = sys.argv[2] if len(sys.argv) > 2 else "screenshot.png"
    wait = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0
    click = sys.argv[4] if len(sys.argv) > 4 else None
    asyncio.run(capture(url, out, wait, click))
