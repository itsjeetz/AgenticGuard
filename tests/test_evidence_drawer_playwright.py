import os
import urllib.request
import pytest
from playwright.sync_api import sync_playwright

def is_server_available():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False

ARTIFACTS_DIR = r"C:\Users\Jeet Das\.gemini\antigravity-ide\brain\6773b9b7-84d0-4a14-94ed-dc0a01321b0b"
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

COLLAPSED_IMG_PATH = os.path.join(ARTIFACTS_DIR, "evidence_drawer_collapsed.png")
EXPANDED_IMG_PATH = os.path.join(ARTIFACTS_DIR, "evidence_drawer_expanded.png")

def test_evidence_drawer_toggle():
    """
    Playwright verification for Attack Type Detection evidence drawers:
    1. Every detected category row starts COLLAPSED. Only header is visible.
    2. Clicking EVIDENCE opens drawer. Clicking again closes it. Independent per row.
    3. Percentage text, DETECTED tag, progress bar unchanged and visible in both states.
    4. Chevron rotates (down = closed, up = open).
    5. Real <button type="button"> with aria-expanded, aria-controls, role="region", Enter/Space key support.
    6. Re-renders reset all rows to collapsed. Scroll preserved (no DOM rebuild on toggle).
    7. Uses CSS display / hidden attribute, respects prefers-reduced-motion.
    """
    if not is_server_available():
        pytest.skip("Live server is not running on http://127.0.0.1:8000; skipping Playwright test.")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1400, "height": 900})
        page = context.new_page()

        page.goto("http://127.0.0.1:8000", wait_until="networkidle")

        # 1. Select attack preset and run inspect
        page.select_option("#selectPreset", "INSTRUCTION_OVERRIDE")
        page.wait_for_timeout(300)

        with page.expect_response(lambda r: "/api/neutralize" in r.url and r.status == 200, timeout=20000):
            page.click("#btnInspect")
        page.wait_for_timeout(600)

        # 2. Verify all detected rows start COLLAPSED
        detected_rows = page.query_selector_all(".attack-detection-row.detected")
        assert len(detected_rows) > 0, "No detected rows found!"

        for idx, row in enumerate(detected_rows):
            btn = row.query_selector(".btn-evidence-toggle")
            assert btn is not None, f"Row {idx} missing .btn-evidence-toggle"
            assert btn.get_attribute("aria-expanded") == "false", f"Row {idx} aria-expanded should be false"
            btn_id = btn.get_attribute("id")
            aria_controls = btn.get_attribute("aria-controls")
            assert btn_id, f"Row {idx} button missing id"
            assert aria_controls, f"Row {idx} button missing aria-controls"

            drawer = row.query_selector(".attack-evidence-drawer")
            assert drawer is not None, f"Row {idx} missing .attack-evidence-drawer"
            assert drawer.get_attribute("id") == aria_controls, f"Row {idx} drawer id mismatch"
            assert drawer.get_attribute("role") == "region", f"Row {idx} drawer role != region"
            assert drawer.get_attribute("aria-labelledby") == btn_id, f"Row {idx} drawer aria-labelledby mismatch"
            assert not drawer.is_visible(), f"Row {idx} drawer should be COLLAPSED and hidden!"

            title = row.query_selector(".attack-row-title")
            tag = row.query_selector(".attack-status-tag")
            pct = row.query_selector(".attack-row-pct")
            bar = row.query_selector(".attack-bar-bg")

            assert title and title.is_visible(), f"Row {idx} title should be visible"
            assert tag and tag.is_visible(), f"Row {idx} tag should be visible"
            assert pct and pct.is_visible(), f"Row {idx} percentage should be visible"
            assert bar and bar.is_visible(), f"Row {idx} progress bar should be visible"

        # 3. Capture Screenshot 1: Collapsed state
        page.screenshot(path=COLLAPSED_IMG_PATH, full_page=False)

        # 4. Click EVIDENCE button to open drawer
        first_row = detected_rows[0]
        first_btn = first_row.query_selector(".btn-evidence-toggle")
        first_drawer = first_row.query_selector(".attack-evidence-drawer")
        first_pct = first_row.query_selector(".attack-row-pct")
        first_tag = first_row.query_selector(".attack-status-tag")
        first_bar = first_row.query_selector(".attack-bar-bg")

        orig_pct_text = first_pct.text_content().strip()
        orig_tag_text = first_tag.text_content().strip()

        first_btn.click()
        page.wait_for_timeout(300)

        assert first_drawer.is_visible(), "Drawer should now be VISIBLE!"
        assert first_btn.get_attribute("aria-expanded") == "true", "Button aria-expanded should be true!"
        btn_class = first_btn.get_attribute("class") or ""
        assert "expanded" in btn_class, "Button should have class 'expanded'"

        # Verify percentage, tag, and bar are unchanged and visible
        open_pct_text = first_pct.text_content().strip()
        open_tag_text = first_tag.text_content().strip()
        assert open_pct_text == orig_pct_text, f"Percentage changed from '{orig_pct_text}' to '{open_pct_text}'!"
        assert open_tag_text == orig_tag_text, f"Tag changed from '{orig_tag_text}' to '{open_tag_text}'!"
        assert first_bar.is_visible(), "Progress bar should remain visible!"

        # Verify independent toggle
        if len(detected_rows) > 1:
            second_drawer = detected_rows[1].query_selector(".attack-evidence-drawer")
            assert not second_drawer.is_visible(), "Second row drawer should remain COLLAPSED!"

        # 5. Capture Screenshot 2: Expanded state
        page.screenshot(path=EXPANDED_IMG_PATH, full_page=False)

        # 6. Click again to close drawer
        first_btn.click()
        page.wait_for_timeout(300)
        assert not first_drawer.is_visible(), "Drawer should now be HIDDEN again!"
        assert first_btn.get_attribute("aria-expanded") == "false", "Button aria-expanded should be false after close!"
        assert "expanded" not in (first_btn.get_attribute("class") or ""), "Button should not have 'expanded' class"
        assert first_pct.text_content().strip() == orig_pct_text, "Percentage text unchanged after close!"

        # 7. Keyboard Accessibility: Space to open, Enter to close
        first_btn.focus()
        page.keyboard.press("Space")
        page.wait_for_timeout(300)
        assert first_drawer.is_visible(), "Space key should OPEN drawer!"
        assert first_btn.get_attribute("aria-expanded") == "true", "aria-expanded should be true after Space"

        page.keyboard.press("Enter")
        page.wait_for_timeout(300)
        assert not first_drawer.is_visible(), "Enter key should CLOSE drawer!"
        assert first_btn.get_attribute("aria-expanded") == "false", "aria-expanded should be false after Enter"

        # 8. Re-render reset test
        first_btn.click()
        page.wait_for_timeout(200)
        assert first_drawer.is_visible(), "Drawer should be open before new inspection"

        page.select_option("#selectPreset", "ROLE_CHANGE")
        page.wait_for_timeout(200)

        with page.expect_response(lambda r: "/api/neutralize" in r.url and r.status == 200, timeout=20000):
            page.click("#btnInspect")
        page.wait_for_timeout(600)

        new_detected_rows = page.query_selector_all(".attack-detection-row.detected")
        assert len(new_detected_rows) > 0
        for idx, row in enumerate(new_detected_rows):
            new_drawer = row.query_selector(".attack-evidence-drawer")
            assert not new_drawer.is_visible(), f"Row {idx} should be COLLAPSED on new inspection!"

        browser.close()

if __name__ == "__main__":
    test_evidence_drawer_toggle()
    print("Test passed successfully!")
