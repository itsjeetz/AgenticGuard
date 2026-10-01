import asyncio
from playwright.async_api import async_playwright

async def inspect_styles():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:8000")
        await page.wait_for_timeout(500)

        # Evaluate computed styles
        styles = await page.evaluate("""() => {
            const body = window.getComputedStyle(document.body);
            const guard = window.getComputedStyle(document.querySelector('.logo-text h1 span'));
            const activeTab = window.getComputedStyle(document.querySelector('.nav-tab.active'));
            const btnInspect = window.getComputedStyle(document.getElementById('btnInspect'));
            const toggleBtn = window.getComputedStyle(document.getElementById('themeToggleBtn'));
            const sunIcon = window.getComputedStyle(document.querySelector('.sun-icon'));
            const moonIcon = window.getComputedStyle(document.querySelector('.moon-icon'));
            const attackSection = document.getElementById('attackDetectionSection');
            const attackRows = document.querySelectorAll('.attack-detection-row');

            return {
                bodyBg: body.backgroundColor,
                bodyColor: body.color,
                guardColor: guard.color,
                activeTabColor: activeTab.color,
                activeTabBorder: activeTab.borderBottomColor,
                btnInspectBg: btnInspect.backgroundImage || btnInspect.backgroundColor,
                btnInspectColor: btnInspect.color,
                toggleBtnBg: toggleBtn.backgroundColor,
                sunDisplay: sunIcon.display,
                moonDisplay: moonIcon.display,
                attackRowsCount: attackRows.length,
                attackSectionRect: attackSection.getBoundingClientRect(),
            };
        }""")

        print("=== Computed Styles in Light Mode ===")
        for k, v in styles.items():
            print(f"{k}: {v}")

        # Now click toggle and check dark mode
        await page.click("#themeToggleBtn")
        await page.wait_for_timeout(300)

        dark_styles = await page.evaluate("""() => {
            const body = window.getComputedStyle(document.body);
            const sunIcon = window.getComputedStyle(document.querySelector('.sun-icon'));
            const moonIcon = window.getComputedStyle(document.querySelector('.moon-icon'));
            const themeAttr = document.documentElement.getAttribute('data-theme');
            return {
                themeAttr,
                bodyBg: body.backgroundColor,
                sunDisplay: sunIcon.display,
                moonDisplay: moonIcon.display,
            };
        }""")

        print("\n=== Computed Styles after Theme Toggle (Dark Mode) ===")
        for k, v in dark_styles.items():
            print(f"{k}: {v}")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(inspect_styles())
