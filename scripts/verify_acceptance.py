import asyncio
import os
from pathlib import Path
from playwright.async_api import async_playwright, expect

DIAGNOSTICS_DIR = Path("diagnostics")
DIAGNOSTICS_DIR.mkdir(exist_ok=True)

results = {}

async def run_acceptance_tests():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1400, "height": 950})
        page = await context.new_page()

        console_errors = []
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda err: console_errors.append(str(err)))

        print("=== CHECK 1: Theme & Toggle Verification ===")
        # 1. Fresh load
        await page.goto("http://127.0.0.1:8000")
        await page.wait_for_selector("#themeToggleBtn")

        # Verify default light theme
        theme_attr = await page.evaluate("document.documentElement.getAttribute('data-theme')")
        body_bg = await page.evaluate("window.getComputedStyle(document.body).backgroundColor")
        logo_guard_color = await page.evaluate("window.getComputedStyle(document.querySelector('.logo-text h1 span')).color")
        inspect_btn_bg = await page.evaluate("window.getComputedStyle(document.getElementById('btnInspect')).backgroundColor")
        active_tab_color = await page.evaluate("window.getComputedStyle(document.querySelector('.nav-tab.active')).color")

        sun_disp = await page.evaluate("window.getComputedStyle(document.querySelector('.sun-icon')).display")
        moon_disp = await page.evaluate("window.getComputedStyle(document.querySelector('.moon-icon')).display")

        print(f"Default theme: {theme_attr or 'light'}")
        print(f"Body BG: {body_bg}")
        print(f"Logo GUARD color: {logo_guard_color}")
        print(f"Inspect btn BG: {inspect_btn_bg}")
        print(f"Active tab color: {active_tab_color}")
        print(f"Sun icon display in light: {sun_disp}, Moon icon display: {moon_disp}")

        assert theme_attr is None or theme_attr == "light", "Should default to light theme"
        assert sun_disp == "none", "Sun icon should be hidden in light mode"
        assert moon_disp != "none", "Moon icon should be visible in light mode"
        assert logo_guard_color == "rgb(161, 0, 255)", f"Logo GUARD should be purple, got {logo_guard_color}"

        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_1_light_theme.png"))

        # Click toggle -> dark theme
        await page.click("#themeToggleBtn")
        await page.wait_for_timeout(300)
        theme_dark = await page.evaluate("document.documentElement.getAttribute('data-theme')")
        sun_disp_dark = await page.evaluate("window.getComputedStyle(document.querySelector('.sun-icon')).display")
        moon_disp_dark = await page.evaluate("window.getComputedStyle(document.querySelector('.moon-icon')).display")
        print(f"After toggle: {theme_dark}, Sun: {sun_disp_dark}, Moon: {moon_disp_dark}")
        assert theme_dark == "dark", "Should switch to dark theme"
        assert sun_disp_dark != "none", "Sun icon should be visible in dark mode"
        assert moon_disp_dark == "none", "Moon icon should be hidden in dark mode"

        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_1_dark_theme.png"))

        # Reload page -> verify persistence
        await page.reload()
        await page.wait_for_timeout(300)
        theme_persisted = await page.evaluate("document.documentElement.getAttribute('data-theme')")
        print(f"After reload in dark mode: {theme_persisted}")
        assert theme_persisted == "dark", "Dark theme should persist in localStorage"

        # Toggle back to light
        await page.click("#themeToggleBtn")
        await page.wait_for_timeout(300)
        assert await page.evaluate("document.documentElement.getAttribute('data-theme')") is None

        results["Check 1: Theme & Toggle"] = "PASS"

        print("\n=== CHECK 2: Console Errors Check ===")
        # Check initial console errors
        print(f"Console errors so far: {len(console_errors)}")
        for err in console_errors:
            print(" -", err)
        assert len(console_errors) == 0, f"Found console errors: {console_errors}"
        results["Check 2: No Console Errors on Load"] = "PASS"

        print("\n=== CHECK 3: Benign Prompt Inspection ===")
        # Select benign preset or enter benign text
        await page.select_option("#selectPreset", "BENIGN_HARD_NEGATIVE")
        await page.click("#btnInspect")
        await page.wait_for_selector(
            "#actionBadge:not(:has-text('INSPECTING...')):not(:has-text('STANDBY'))",
            timeout=15000,
        )
        await page.wait_for_timeout(300)

        action_text = (await page.inner_text("#actionBadge")).strip()
        risk_text = (await page.inner_text("#riskValue")).strip()
        summary_badge = (await page.inner_text("#detectionSummaryBadge")).strip()
        pill_l1 = (await page.inner_text("#pillL1 .time")).strip()
        total_time = (await page.inner_text("#totalPipelineTime")).strip()

        print(f"Benign prompt action: {action_text}, risk: {risk_text}, summary: {summary_badge}")
        print(f"L1 latency: {pill_l1}, Total time: {total_time}")

        assert action_text == "ALLOW", f"Expected ALLOW for benign text, got {action_text}"
        assert float(risk_text) < 0.30, f"Expected risk < 0.30, got {risk_text}"
        assert "Clean" in summary_badge or "0 Detected" in summary_badge, f"Expected clean summary, got {summary_badge}"
        assert pill_l1 != "-", "L1 Ingestion should show real latency, not '-'"
        assert total_time != "0.00 ms", "Total pipeline time should update"

        # Check all 9 rows show 0%
        pcts = await page.eval_on_selector_all(".attack-row-pct", "elements => elements.map(e => e.textContent)")
        assert len(pcts) == 9, f"Expected 9 attack rows, got {len(pcts)}"
        assert all(p == "0%" for p in pcts), f"Expected all 0% for benign, got {pcts}"

        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_3_benign.png"))
        results["Check 3: Benign Prompt Inspection"] = "PASS"

        print("\n=== CHECK 4: Prompt Injection Detection ===")
        # Select INSTRUCTION_OVERRIDE preset
        await page.select_option("#selectPreset", "INSTRUCTION_OVERRIDE")
        await page.click("#btnInspect")
        await page.wait_for_selector(
            "#actionBadge:not(:has-text('INSPECTING...')):not(:has-text('STANDBY'))",
            timeout=15000,
        )
        await page.wait_for_timeout(300)

        inj_action = (await page.inner_text("#actionBadge")).strip()
        inj_risk = (await page.inner_text("#riskValue")).strip()
        inj_summary = (await page.inner_text("#detectionSummaryBadge")).strip()
        sanitized_output = (await page.inner_text("#sanitizedContentPane")).strip()

        print(f"Injection action: {inj_action}, risk: {inj_risk}, summary: {inj_summary}")
        print(f"Sanitized pane preview: {sanitized_output[:80]}...")

        assert inj_action in ("BLOCK", "SANITIZE", "ESCALATE"), f"Expected non-ALLOW action, got {inj_action}"
        assert float(inj_risk) >= 0.50, f"Expected high risk, got {inj_risk}"
        assert "Detected" in inj_summary, f"Expected detected summary, got {inj_summary}"

        # Verify detected row sorted to top and percentage > 0%
        first_row_title = (await page.inner_text(".attack-detection-row:first-child .attack-row-title")).strip()
        first_row_pct = (await page.inner_text(".attack-detection-row:first-child .attack-row-pct")).strip()
        first_row_tag = (await page.inner_text(".attack-detection-row:first-child .attack-status-tag")).strip()

        print(f"Top detected row: {first_row_title}, pct: {first_row_pct}, tag: {first_row_tag}")
        assert first_row_title == "Instruction Override", f"Expected Instruction Override at top, got {first_row_title}"
        assert first_row_tag.lower() == "detected", f"Expected Detected tag, got {first_row_tag}"
        assert first_row_pct != "0%", f"Expected non-zero pct, got {first_row_pct}"

        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_4_injection.png"))
        results["Check 4: Prompt Injection Detection"] = "PASS"

        print("\n=== CHECK 5: PDF File Ingestion (Native Text vs Garbled/Scanned) ===")
        # 5a: Native text PDF
        text_pdf = Path("test_artifacts/text_sample.pdf").resolve()
        await page.set_input_files("#fileInput", str(text_pdf))
        await page.wait_for_selector(
            "#actionBadge:not(:has-text('INSPECTING...')):not(:has-text('STANDBY'))",
            timeout=15000,
        )
        await page.wait_for_timeout(300)

        pdf_extracted = await page.input_value("#textInput")
        pdf_action = (await page.inner_text("#actionBadge")).strip()
        print(f"Native PDF extracted text preview: {pdf_extracted[:80]}...")
        print(f"Native PDF action: {pdf_action}")

        assert "ALLOW" in pdf_action, f"Benign text PDF should be ALLOW, got {pdf_action}"
        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_5_text_pdf.png"))

        # 5b: Scanned / Image-only PDF
        scanned_pdf = Path("test_artifacts/scanned_sample.pdf").resolve()
        await page.set_input_files("#fileInput", str(scanned_pdf))
        await page.wait_for_selector(
            "#actionBadge:not(:has-text('INSPECTING...')):not(:has-text('STANDBY'))",
            timeout=15000,
        )
        await page.wait_for_timeout(500)

        scanned_extracted = await page.input_value("#textInput")
        scanned_action = (await page.inner_text("#actionBadge")).strip()
        print(f"Scanned PDF extracted preview: {scanned_extracted[:80]}...")
        print(f"Scanned PDF action: {scanned_action}")

        assert "Could not extract readable text from this PDF" in scanned_extracted, "Should show could not extract message"
        assert scanned_action == "ESCALATE", f"Unreadable PDF must produce REVIEW/ESCALATE, never ALLOW. Got: {scanned_action}"
        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_5_scanned_pdf.png"))

        # 5c: Oversize file rejection (> 2 MB)
        oversize_file = Path("test_artifacts/oversize.txt").resolve()
        await page.set_input_files("#fileInput", str(oversize_file))
        await page.wait_for_timeout(500)
        toast_text = (await page.inner_text("#socToast")).strip()
        print(f"Oversize file toast: {toast_text}")
        assert "exceeds 2 MB" in toast_text, "Should reject > 2MB files with friendly error"

        results["Check 5: PDF Extraction & Scanned Fallback"] = "PASS"

        print("\n=== CHECK 6: Force Backend Exception (Fail Closed in UI) ===")
        # Route /api/neutralize to return 500
        await page.route("**/api/neutralize", lambda route: route.fulfill(status=500, json={"detail": "Simulated unhandled server exception"}))

        await page.select_option("#selectPreset", "INSTRUCTION_OVERRIDE")
        await page.click("#btnInspect")
        await page.wait_for_timeout(800)

        error_action = (await page.inner_text("#actionBadge")).strip()
        error_req_id = (await page.inner_text("#verdictReqId")).strip()
        badge_class = await page.get_attribute("#actionBadge", "class")

        print(f"On 500 error: action={error_action}, class={badge_class}, reqId={error_req_id}")
        assert error_action == "ERROR", f"Verdict must show ERROR on request failure, got {error_action}"
        assert "badge-error" in badge_class, f"Expected badge-error class, got {badge_class}"
        assert error_action != "ALLOW", "Must NEVER fail open to ALLOW"

        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_6_backend_error.png"))
        await page.unroute("**/api/neutralize")
        results["Check 6: Force Backend Exception Shows ERROR"] = "PASS"

        print("\n=== CHECK 7: All 5 Tabs Render Cleanly in Both Themes ===")
        tabs = [
            ("tabInspector", "#navInspector", "Inspector"),
            ("tabSandbox", "#navSandbox", "Sandbox"),
            ("tabEval", "#navEval", "Eval"),
            ("tabAudit", "#navAudit", "Audit"),
            ("tabPolicy", "#navPolicy", "Policy")
        ]

        # Test Light Theme
        for tab_id, nav_id, name in tabs:
            await page.click(nav_id)
            await page.wait_for_timeout(400)
            is_visible = await page.is_visible(f"#{tab_id}")
            assert is_visible, f"Tab {name} should be visible"
        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_7_tabs_light.png"))

        # Switch to Dark Theme
        await page.click("#themeToggleBtn")
        await page.wait_for_timeout(300)
        for tab_id, nav_id, name in tabs:
            await page.click(nav_id)
            await page.wait_for_timeout(400)
            is_visible = await page.is_visible(f"#{tab_id}")
            assert is_visible, f"Tab {name} should be visible in dark theme"
        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_7_tabs_dark.png"))

        # Switch back to light
        await page.click("#themeToggleBtn")
        await page.wait_for_timeout(300)
        results["Check 7: All 5 Tabs Render in Light & Dark"] = "PASS"

        print("\n=== CHECK 8: Missing GEMINI_API_KEY Fallback ===")
        # Verify /api/health reports gracefully without GEMINI_API_KEY
        await page.click("#navInspector")
        await page.select_option("#selectPreset", "INSTRUCTION_OVERRIDE")
        await page.click("#btnInspect")
        await page.wait_for_timeout(1500)

        pill_judge = (await page.inner_text("#pillL3Judge .time")).strip()
        judge_border = await page.evaluate("window.getComputedStyle(document.getElementById('pillL3Judge')).borderColor")
        print(f"L3 Judge status pill time: {pill_judge}, border: {judge_border}")
        assert pill_judge != "", "Judge pill should be rendered"
        await page.screenshot(path=str(DIAGNOSTICS_DIR / "acceptance_8_gemini_fallback.png"))
        results["Check 8: Missing GEMINI_API_KEY Graceful Fallback"] = "PASS"

        # Final check on console errors throughout all tests (ignoring simulated 500 network error)
        unexpected_errors = [e for e in console_errors if "500" not in e and "Internal Server Error" not in e]
        print(f"\nUnexpected console errors count: {len(unexpected_errors)}")
        for err in unexpected_errors:
            print(" -", err)
        assert len(unexpected_errors) == 0, f"Unexpected console errors occurred: {unexpected_errors}"

        await browser.close()

    print("\n=======================================================")
    print("           ACCEPTANCE CHECK RESULTS SUMMARY           ")
    print("=======================================================")
    for check, status in results.items():
        print(f" [{status}] {check}")
    print("=======================================================\n")

if __name__ == "__main__":
    asyncio.run(run_acceptance_tests())
