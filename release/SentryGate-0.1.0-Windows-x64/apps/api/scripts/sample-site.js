import http from "node:http";

const port = Number(process.env.SAMPLE_SITE_PORT ?? 4320);
const server = http.createServer(async (req, res) => {
  if (req.method === "POST" && req.url?.startsWith("/upload")) {
    let bytes = 0;
    for await (const chunk of req) bytes += chunk.length;
    const body = JSON.stringify({ uploadedBytes: bytes, method: req.method, path: req.url });
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), "X-Sample-Site": "sentrygate-local-sample" });
    return res.end(body);
  }
  const page = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SentryGate sample website</title><style>body{font:16px system-ui;max-width:700px;margin:60px auto;padding:0 20px;color:#203229}h1{color:#216348}form{display:flex;gap:10px;align-items:center;margin:24px 0;padding:16px;border:1px solid #ccd8d0;border-radius:6px}button{padding:9px 14px;background:#216348;color:white;border:0;border-radius:4px}code{background:#eef3ef;padding:3px 5px}</style><h1>Local sample website</h1><p>This page is served by a local upstream. Requests through SentryGate are streamed to this process.</p><form method="post" action="upload" enctype="multipart/form-data"><input type="file" name="sample"><button>Upload through gateway</button></form><p>Probe path: <code>/.env</code></p></html>`;
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(page), "X-Sample-Site": "sentrygate-local-sample" });
  res.end(page);
});

server.listen(port, "127.0.0.1", () => console.log(`Sample website running at http://127.0.0.1:${port}`));
