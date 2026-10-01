import asyncio
import os
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        console_logs = []
        page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
        page.on("pageerror", lambda err: console_logs.append(f"[PAGE_ERROR] {err}"))

        print("Navigating to http://127.0.0.1:8000 ...")
        await page.goto("http://127.0.0.1:8000")
        await page.wait_for_timeout(1000)

        # 1. Take initial screenshot
        os.makedirs("diagnostics", exist_ok=True)
        await page.screenshot(path="diagnostics/initial_landing.png")
        print("Captured diagnostics/initial_landing.png")

        # 2. Check title and theme
        title = await page.title()
        print("Title:", title)
        data_theme = await page.evaluate("document.documentElement.getAttribute('data-theme')")
        print("Initial data-theme:", data_theme)

        # 3. Check attack detection panel state
        attack_text = await page.inner_text("#attackDetectionSection")
        print("Attack detection section initial text:\n", attack_text.strip()[:200])

        # 4. Click Inspect & Neutralize with Preset 1
        print("\nSelecting preset 1 and clicking Inspect & Neutralize...")
        await page.select_option("#selectPreset", "INSTRUCTION_OVERRIDE")
        await page.click("#btnInspect")
        await page.wait_for_timeout(2000)

        await page.screenshot(path="diagnostics/after_inspect.png")
        print("Captured diagnostics/after_inspect.png")

        verdict_action = await page.inner_text("#actionBadge")
        print("Verdict action:", verdict_action)
        risk_value = await page.inner_text("#riskValue")
        print("Risk value:", risk_value)

        # Print all console messages
        print("\n=== Console Logs Recorded ===")
        for log in console_logs:
            print(log)

        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
