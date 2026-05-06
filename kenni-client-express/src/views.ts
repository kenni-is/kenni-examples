type IndexProps = {
  signedIn: boolean;
  name: string;
  apiEnabled: boolean;
  m2mEnabled: boolean;
};

const escape = (s: string) =>
  s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

export function renderIndex(props: IndexProps): string {
  const { signedIn, name, apiEnabled, m2mEnabled } = props;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Kenni — Express example</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
      max-width: 720px;
      margin: 60px auto;
      padding: 0 24px;
      color: #111;
    }
    h1 { font-size: 28px; margin-bottom: 24px; }
    .button-stack { display: flex; flex-direction: column; gap: 12px; align-items: stretch; width: 260px; }
    .button-stack button {
      padding: 10px 16px;
      font-size: 14px;
      border: 1px solid #999;
      border-radius: 6px;
      background: #fff;
      cursor: pointer;
    }
    .button-stack button:hover { background: #f3f3f3; }
    pre.details {
      margin-top: 24px;
      max-width: 600px;
      padding: 16px;
      border-radius: 8px;
      background: rgba(127, 127, 127, 0.12);
      font-family: ui-monospace, "SF Mono", Menlo, monospace;
      font-size: 13px;
      white-space: pre-wrap;
      word-wrap: break-word;
    }
    form { margin: 0; }
  </style>
</head>
<body>
  <h1>${signedIn ? `Welcome ${escape(name)}` : "Kenni — Express example"}</h1>

  <div class="button-stack">
    ${!signedIn ? `<form method="get" action="/auth/login"><button type="submit">Continue with Kenni</button></form>` : ""}

    ${signedIn && apiEnabled ? `<button type="button" data-fetch-url="/api/me">Call protected resource</button>` : ""}

    ${m2mEnabled ? `<button type="button" data-fetch-url="/api/client-credentials" data-fetch-method="POST">Client credentials grant</button>` : ""}

    ${
      signedIn
        ? `<form method="post" action="/auth/logout"><button type="submit">Sign out (local)</button></form>
           <form method="post" action="/auth/rp-logout"><button type="submit">RP-initiated logout</button></form>`
        : ""
    }
  </div>

  <pre class="details" id="output" hidden></pre>

  <script>
    const output = document.getElementById("output");
    document.querySelectorAll("[data-fetch-url]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const method = btn.dataset.fetchMethod || "GET";
        let body;
        try {
          const r = await fetch(btn.dataset.fetchUrl, { method });
          body = await r.json();
        } catch (e) {
          body = { error: String(e) };
        }
        output.hidden = false;
        output.textContent = JSON.stringify(body, null, 2);
      });
    });
  </script>
</body>
</html>`;
}
