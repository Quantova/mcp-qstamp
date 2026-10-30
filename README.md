# mcp-qstamp

Post quantum on chain audit for Model Context Protocol tool calls.

The Model Context Protocol ships no signing and no audit of tool calls. A server can run a tool and return a result, and nothing proves afterward what the tool did or that the record of it was not edited. This package fills that gap. It wraps a tool handler so every invocation is fingerprinted and anchored as a post quantum Qstamp receipt on the Quantova network, while the call data stays on the server.

Only the 32 byte digest of each call leaves the process. The arguments and the result stay with you. An auditor who holds the record recomputes the digest and checks it against the anchored commitment, so the content stays private while the proof that the call happened in one exact form at a point in time is public and tamper evident.

## Install

```
npm install @quantovainc/mcp-qstamp @quantovainc/qstamp
```

## Use

```ts
import { McpServer } from '@modelcontextprotocol/server';
import * as qstamp from '@quantovainc/qstamp';
import { QstampToolAudit } from '@quantovainc/mcp-qstamp';

const audit = new QstampToolAudit({
	qstamp,
	seed: mySigningSeed,
	index: 0,
	kind: 7757,
	onReceipt(receipt, name) {
		store(name, receipt);
	},
});

server.registerTool(
	'search',
	{ description: 'search the index' },
	audit.wrap('search', async (args) => {
		return { content: [{ type: 'text', text: run(args.q) }] };
	}),
);
```

The wrapped handler runs the original tool, anchors the call, and returns the original result. An audit layer must never break the tool it wraps, so a failure to anchor is routed to the onError callback and the tool result is returned unchanged. Pass onError to observe anchoring failures.

## What is anchored

By default the receipt binds the tool name and the result. Pass a project function to choose exactly what is committed, for example to include the arguments.

```ts
new QstampToolAudit({
	qstamp,
	seed,
	index: 0,
	project: (name, args, result) => ({ name, args, result }),
});
```

The projection is serialized in a canonical form so the digest does not depend on object key order, and two runs of the same call produce the same digest.

## Verifying

Receipts verify with the reference Qstamp SDK, or offline in Go with the qstamp-go module.

## Tests

```
npm run build
npm test
```

The suite covers the wrap and record paths, the privacy property that neither the arguments nor the result reach the stamp call, a deterministic digest, pass through of handler arguments, the guarantee that a tool still succeeds when anchoring fails with and without an error handler, and rejection of bad construction.

## License

Apache 2.0 or MIT. See the LICENSE files.
