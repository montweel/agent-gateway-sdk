# "AI Refund Disaster" demo

A 60-second, split-screen demo of an AI support agent being prompt-injected into refunding every
order and wiping the customer table, with and without Mont Agent Gateway in front of the store API.

Everything is simulated locally (mock store, scripted agent). No real store, payment provider or money is involved.

```bash
npm install            # once, at the repo root
npm run demo:shopify   # http://127.0.0.1:4100  (DEMO_PORT to change)
```

## Recording script

1. **Protection OFF** → click **Simulate Indirect Prompt Injection Attack**. The hidden instruction in the
   customer ticket makes the agent fire 20 × `POST /api/shopify/refund` (`{ orderId, amount: 250, reason }`)
   at machine speed and then `DELETE /api/shopify/customers`. Balance goes $5,000 → $0 in about 2 seconds,
   and the customer table is wiped.
2. **Reset**, switch to **Mont Gateway ON**, attack again:
   - `DELETE /api/shopify/customers` → **403 BLOCKED** (deterministic rule).
   - Refund #1 → **202 HELD**: `body.amount = 250 > 100`, so it lands in the approval panel with the
     payload, caller, the agent's stated reason and `amount` flagged as high-risk.
   - Refunds #2–#20 → **429 RATE-LIMITED** (1 per minute on this endpoint stops the loop).
3. Click **Reject** (or **Approve** to show exactly one $250 refund going through).

## The rules it uses

```json
{
  "POST /api/shopify/refund": {
    "mode": "REQUIRE_APPROVAL",
    "rateLimit": 1,
    "policies": [
      { "name": "auto-refund up to $100", "when": [{ "field": "body.amount", "op": "<=", "value": 100 }],  "mode": "ALLOW" },
      { "name": "never above $1,000",     "when": [{ "field": "body.amount", "op": ">",  "value": 1000 }], "mode": "BLOCK" }
    ]
  },
  "DELETE /api/shopify/customers": { "mode": "BLOCK" }
}
```

The UI is a generic merchant dashboard ("Acme Outfitters"); it does not use any platform's logo or branding.
