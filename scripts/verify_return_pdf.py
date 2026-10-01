import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1400, "height": 950})

        console_logs = []
        page_errors = []

        page.on("console", lambda m: console_logs.append(f"[{m.type}] {m.text} (loc: {m.location})"))
        page.on("pageerror", lambda e: page_errors.append(str(e)))

        print("Navigating to http://127.0.0.1:8000/ ...")
        await page.goto("http://127.0.0.1:8000/")
        await page.wait_for_timeout(1000)

        file_input = page.locator("#fileInput")
        print("Uploading test_artifacts/Return.pdf ...")
        await file_input.set_input_files("test_artifacts/Return.pdf")

        # Wait for the actionBadge to be populated with real verdict (ALLOW)
        await page.wait_for_function(
            "() => document.getElementById('actionBadge').textContent === 'ALLOW' || document.getElementById('actionBadge').textContent === 'ERROR'",
            timeout=25000,
        )
        await page.wait_for_timeout(1500)

        # Check footer
        footer_text = await page.locator("#socFooter").inner_text()
        print("=== FOOTER TEXT ===")
        print(footer_text.strip())

        # Check textarea value
        textarea = page.locator("#textInput")
        text_val = await textarea.input_value()
        print("\n=== TEXTAREA VALUE (first 400 chars) ===")
        print(repr(text_val[:400]))

        print("\n=== MOJIBAKE & CONTENT CHECKS ===")
        print("Contains Ùæ×:", "Ùæ×" in text_val)
        print("Contains Âîæ:", "Âîæ" in text_val)
        print("Contains BDMPD7425C (PAN):", "BDMPD7425C" in text_val)
        print("Contains 2025-26 (AY):", "2025-26" in text_val)

        verdict_badge = await page.locator("#actionBadge").inner_text()
        risk_val = await page.locator("#riskValue").inner_text()
        print(f"\nVerdict Action: {verdict_badge}, Risk: {risk_val}")

        # Check 9 attack vector rows
        rows = await page.locator(".attack-detection-row").count()
        summary_badge = await page.locator("#detectionSummaryBadge").inner_text()
        print(f"Rendered attack detection rows: {rows}, Summary: {summary_badge}")

        # Check cascade layer pills
        pill_l1 = await page.locator("#pillL1 .time").inner_text()
        pill_l5 = await page.locator("#pillL5 .time").inner_text()
        total_time = await page.locator("#totalPipelineTime").inner_text()
        print(f"Pill L1: {pill_l1}, Pill L5: {pill_l5}, Total Pipeline Time: {total_time}")

        print("\n=== CONSOLE LOGS ===")
        for l in console_logs:
            print(l)

        print("\n=== PAGE ERRORS ===")
        for e in page_errors:
            print(e)

        await page.screenshot(path="diagnostics/return_pdf_complete_verified.png", full_page=True)
        print("\nScreenshot saved to diagnostics/return_pdf_complete_verified.png")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
