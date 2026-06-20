type ScanRequest = {
  files: Array<{ path: string; content: string }>;
};

const payload: ScanRequest = {
  files: [
    {
      path: ".mcp.json",
      content: JSON.stringify({
        mcpServers: {
          github: {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-github"],
            env: { GITHUB_TOKEN: "R3pQ9vLm7Ks2Qa8Zp0Nv6Xy4" }
          }
        }
      })
    }
  ]
};

const response = await fetch("http://127.0.0.1:8080/api/scan/sarif", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(payload)
});

console.log(response.status);
console.log(await response.json());
