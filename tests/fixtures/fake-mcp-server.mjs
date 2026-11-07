// Minimal stdio MCP server used by the test suite. Newline-delimited JSON-RPC 2.0.
// Every tools/call it receives is appended to the file named by FAKE_MCP_LOG, so tests can
// prove which calls actually reached the server.
import fs from "node:fs";
import readline from "node:readline";

const logFile = process.env.FAKE_MCP_LOG;
const send = (m) => process.stdout.write(`${JSON.stringify(m)}\n`);

readline.createInterface({ input: process.stdin }).on("line", (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.id === undefined) return; // notifications
  switch (msg.method) {
    case "initialize":
      send({
        jsonrpc: "2.0",
        id: msg.id,
        result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fake-mcp", version: "1.0.0" } },
      });
      break;
    case "tools/list":
      send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "search_orders" }, { name: "refund_order" }, { name: "delete_customer" }] } });
      break;
    case "tools/call":
      if (logFile) fs.appendFileSync(logFile, `${JSON.stringify(msg.params)}\n`);
      send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `ran ${msg.params.name} ${JSON.stringify(msg.params.arguments ?? {})}` }] } });
      break;
    default:
      send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } });
  }
});
