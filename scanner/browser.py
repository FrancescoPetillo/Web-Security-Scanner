from playwright.sync_api import sync_playwright


def fetch_page(url: str):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        context = browser.new_context()
        page = context.new_page()

        page.goto(url, timeout=10000)

        # 🔥 PRENDI RISPOSTA FINALE
        response = page.wait_for_response(
            lambda r: r.url == page.url and r.status == 200
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