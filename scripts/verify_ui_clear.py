import asyncio
import os
import sys
from pathlib import Path
from playwright.async_api import async_playwright

ARTIFACTS_DIR = Path(r"C:\Users\Jeet Das\.gemini\antigravity-ide\brain\497afe46-e81b-4b98-b8d6-7809a2ee1472\screenshots")
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

async def run_tests():
    console_errors = []
    
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1280, "height": 900})
        
        # Listen for console errors
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda err: console_errors.append(str(err)))
        
        print("Navigating to http://127.0.0.1:8000/...")
        await page.goto("http://127.0.0.1:8000/")
        await page.wait_for_timeout(1000)
        
        # ---------------------------------------------------------------------
        # 1. Verify Top Info Bar in Light Theme
        # ---------------------------------------------------------------------
        print("\n--- Test 1: Top info bar (Light Theme) ---")
        badge_count = await page.locator(".demo-badge").count()
        assert badge_count == 0, f"Expected 0 .demo-badge, found {badge_count}"
        
        sub_text_count = await page.locator("text='Policy edit & retraining disabled'").count()
        assert sub_text_count == 0, f"Expected 0 'Policy edit & retraining disabled', found {sub_text_count}"
        
        # Check required items are present
        assert await page.locator("#demoRateLimit").is_visible(), "#demoRateLimit is not visible"
        assert await page.locator("text='Max Upload: 2 MB'").is_visible(), "Max Upload is not visible"
        assert await page.locator("#demoLlmQuota").is_visible(), "#demoLlmQuota is not visible"
        
        rate_text = await page.locator("#demoRateLimit").text_content()
        quota_text = await page.locator("#demoLlmQuota").text_content()
        print(f"Top bar items: Rate: '{rate_text}', Quota: '{quota_text}'")
        
        # Capture light theme AFTER screenshot
        await page.screenshot(path=str(ARTIFACTS_DIR / "after_light.png"))
        print(f"Captured: {ARTIFACTS_DIR / 'after_light.png'}")
        
        # ---------------------------------------------------------------------
        # Verify Top Info Bar in Dark Theme
        # ---------------------------------------------------------------------
        print("\n--- Test 1b: Top info bar (Dark Theme) ---")
        await page.click("#themeToggleBtn")
        await page.wait_for_timeout(500)
        
        badge_count_dark = await page.locator(".demo-badge").count()
        assert badge_count_dark == 0, "Found .demo-badge in dark mode"
        
        await page.screenshot(path=str(ARTIFACTS_DIR / "after_dark.png"))
        print(f"Captured: {ARTIFACTS_DIR / 'after_dark.png'}")
        
        # Switch back to light theme for subsequent tests
        await page.click("#themeToggleBtn")
        await page.wait_for_timeout(300)
        
        # ---------------------------------------------------------------------
        # 2. Verify Clear button attributes & styling
        # ---------------------------------------------------------------------
        print("\n--- Test 2: Clear button presence & attributes ---")
        clear_btn = page.locator("#btnClearInput")
        assert await clear_btn.is_visible(), "Clear button (#btnClearInput) is not visible"
        btn_text = await clear_btn.text_content()
        assert "Clear" in btn_text, f"Expected 'Clear' in button text, got: {btn_text}"
        aria_label = await clear_btn.get_attribute("aria-label")
        assert aria_label, "Clear button missing aria-label"
        print(f"Clear button verified: text='{btn_text.strip()}', aria-label='{aria_label}'")
        
        # ---------------------------------------------------------------------
        # 3. Paste text, run Inspect, then click Clear
        # ---------------------------------------------------------------------
        print("\n--- Test 3: Paste text, run Inspect, then click Clear ---")
        # Select an attack preset
        await page.select_option("#selectPreset", "INSTRUCTION_OVERRIDE")
        await page.wait_for_timeout(300)
        
        text_before_inspect = await page.locator("#textInput").input_value()
        assert len(text_before_inspect) > 10, "Textarea did not populate from preset"
        
        # Run inspection
        await page.click("#btnInspect")
        # Wait for inspection to finish
        await page.wait_for_selector(".action-badge:not(.badge-idle)", timeout=10000)
        await page.wait_for_timeout(1000)
        
        badge_text = await page.locator("#actionBadge").text_content()
        risk_val = await page.locator("#riskValue").text_content()
        print(f"Inspected verdict: action={badge_text}, risk={risk_val}")
        
        # Capture screenshot of inspected state
        await page.screenshot(path=str(ARTIFACTS_DIR / "inspected_before_clear.png"))
        print(f"Captured: {ARTIFACTS_DIR / 'inspected_before_clear.png'}")
        
        # Click Clear
        await page.click("#btnClearInput")
        await page.wait_for_timeout(500)
        
        # Verify all elements reset to standby:
        # a) Textarea empty and readOnly = false
        val_after_clear = await page.locator("#textInput").input_value()
        assert val_after_clear == "", f"Expected empty textarea, got: {val_after_clear}"
        is_readonly = await page.locator("#textInput").is_editable()
        assert is_readonly is True, "Textarea is not editable after clear"
        
        # b) Dropdowns reset to default
        preset_val = await page.locator("#selectPreset").input_value()
        assert preset_val == "", f"Expected empty preset, got: {preset_val}"
        source_val = await page.locator("#selectSource").input_value()
        assert source_val == "", f"Expected empty carrier/source, got: {source_val}"
        
        # c) Firewall Verdict card to STANDBY with Combined Risk 0.000, clear req id and sha
        verdict_badge = await page.locator("#actionBadge").text_content()
        assert verdict_badge == "STANDBY", f"Expected STANDBY, got: {verdict_badge}"
        risk_after = await page.locator("#riskValue").text_content()
        assert risk_after == "0.000", f"Expected 0.000 risk, got: {risk_after}"
        req_id_text = await page.locator("#verdictReqId").text_content()
        assert req_id_text == "No inspection run yet", f"Expected 'No inspection run yet', got: {req_id_text}"
        
        # d) All 9 Attack Type Detection rows to 0% "Not detected" and badge to "9 Vectors Standby"
        summary_badge = await page.locator("#detectionSummaryBadge").text_content()
        assert summary_badge == "9 Vectors Standby", f"Expected '9 Vectors Standby', got: {summary_badge}"
        
        tags = await page.locator(".attack-status-tag").all_text_contents()
        for tag in tags:
            assert tag.strip() == "Not detected", f"Expected 'Not detected', got '{tag}'"
        pcts = await page.locator(".attack-row-pct").all_text_contents()
        for pct in pcts:
            assert pct.strip() == "0%", f"Expected '0%', got '{pct}'"
            
        # e) Cascade layer pills to "-" and Total Pipeline Time to 0.00 ms
        pill_times = await page.locator(".layer-pill .time").all_text_contents()
        for pt in pill_times:
            assert pt.strip() == "-", f"Expected '-', got '{pt}'"
        total_time = await page.locator("#totalPipelineTime").text_content()
        assert "0.00 ms" in total_time, f"Expected 0.00 ms, got: {total_time}"
        
        # f) Three output panels cleared
        raw_text = await page.locator("#rawContentPane").text_content()
        assert "Raw content will be rendered here" in raw_text, f"Raw pane not cleared: {raw_text}"
        var_text = await page.locator("#variantsContentPane").text_content()
        assert "Normalized variants and decoded tokens will appear here" in var_text, f"Variants pane not cleared: {var_text}"
        san_text = await page.locator("#sanitizedContentPane").text_content()
        assert "Sanitized text and nonce envelope spotlighting will appear here" in san_text, f"Sanitized pane not cleared: {san_text}"
        
        # g) Focus is on textarea
        is_focused = await page.evaluate("() => document.activeElement === document.getElementById('textInput')")
        assert is_focused is True, "Textarea did not receive focus after clear"
        
        # Capture screenshot of cleared state
        await page.screenshot(path=str(ARTIFACTS_DIR / "cleared_after_inspect.png"))
        print(f"Captured: {ARTIFACTS_DIR / 'cleared_after_inspect.png'}")
        print("Test 3 PASSED successfully with all elements in STANDBY state!")
        
        # ---------------------------------------------------------------------
        # 4. Upload a file, click Clear
        # ---------------------------------------------------------------------
        print("\n--- Test 4: Upload file, click Clear ---")
        test_file_path = ARTIFACTS_DIR / "sample_test.txt"
        test_file_path.write_text("Hello from uploaded file for testing Clear button.")
        
        # Set file input
        await page.set_input_files("#fileInput", str(test_file_path))
        await page.wait_for_timeout(1000)
        
        # Verify file is selected and text is read-only preview
        file_display = await page.locator("#fileNameDisplay").text_content()
        assert "sample_test.txt" in file_display, f"Expected filename in display, got: {file_display}"
        
        # Click Clear
        await page.click("#btnClearInput")
        await page.wait_for_timeout(300)
        
        file_display_after = await page.locator("#fileNameDisplay").text_content()
        assert file_display_after == "", f"Expected empty filename display, got: {file_display_after}"
        val_after_file_clear = await page.locator("#textInput").input_value()
        assert val_after_file_clear == "", f"Expected empty textarea, got: {val_after_file_clear}"
        is_editable = await page.locator("#textInput").is_editable()
        assert is_editable is True, "Textarea should be editable after clearing file upload"
        
        print("Test 4 PASSED: file selection and read-only preview cleared successfully!")
        
        # ---------------------------------------------------------------------
        # 5. Click Clear during running inspection (AbortController test)
        # ---------------------------------------------------------------------
        print("\n--- Test 5: Click Clear during running inspection ---")
        await page.fill("#textInput", "Test payload to verify in-flight abort cancel")
        
        # Start inspection
        await page.click("#btnInspect")
        await page.wait_for_timeout(50)  # Immediately while in-flight
        
        # Click Clear while request is in-flight
        await page.click("#btnClearInput")
        
        # Wait 2 seconds to ensure no stale network response repaints the UI
        await page.wait_for_timeout(2000)
        
        # Verify UI remains in standby
        action_st = await page.locator("#actionBadge").text_content()
        assert action_st == "STANDBY", f"Expected STANDBY, but got late repaint: {action_st}"
        text_st = await page.locator("#textInput").input_value()
        assert text_st == "", f"Expected empty textarea, but got: {text_st}"
        
        print("Test 5 PASSED: In-flight inspection cancelled cleanly without stale repaint!")
        
        # ---------------------------------------------------------------------
        # Console error check
        # ---------------------------------------------------------------------
        # Filter out benign favicons if any
        real_errors = [e for e in console_errors if "favicon" not in e.lower()]
        assert len(real_errors) == 0, f"Console errors detected: {real_errors}"
        print("Zero console errors detected during all operations!")
        
        await browser.close()
        print("\nALL PLAYWRIGHT TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    asyncio.run(run_tests())
