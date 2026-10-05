import asyncio
import os
from pathlib import Path
from playwright.async_api import async_playwright

ARTIFACTS_DIR = Path(r"C:\Users\Jeet Das\.gemini\antigravity-ide\brain\497afe46-e81b-4b98-b8d6-7809a2ee1472\screenshots")
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1280, "height": 900})
        
        await page.goto("http://127.0.0.1:8000/")
        await page.wait_for_timeout(1000)
        
        # Ensure demo banner is visible to capture BEFORE state
        await page.evaluate("""() => {
            const b = document.getElementById('demoBanner');
            if (b) b.classList.remove('hidden');
        }""")
        
        # Capture light theme before
        await page.screenshot(path=str(ARTIFACTS_DIR / "before_light.png"))
        print(f"Captured: {ARTIFACTS_DIR / 'before_light.png'}")
        
        # Switch to dark theme
        await page.click("#themeToggleBtn")
        await page.wait_for_timeout(500)
        await page.screenshot(path=str(ARTIFACTS_DIR / "before_dark.png"))
        print(f"Captured: {ARTIFACTS_DIR / 'before_dark.png'}")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
