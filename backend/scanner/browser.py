from playwright.sync_api import sync_playwright

def fetch_page(url: str):
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu"
            ]
        )

        context = browser.new_context()
        page = context.new_page()

        response = page.goto(
            url,
            timeout=15000,
            wait_until="domcontentloaded"
        )

        headers = response.headers if response else {}
        cookies = context.cookies()
        final_url = page.url

        browser.close()

        return {
            "headers": headers,
            "cookies": cookies,
            "url": final_url
        }