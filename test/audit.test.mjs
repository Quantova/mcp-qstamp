import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { QstampToolAudit } from '../dist/index.js';

function fakeQstamp() {
	const calls = [];
	return {
		calls,
		digestBytes(bytes, alg) {
			return Uint8Array.from(createHash(alg === 'sha256' ? 'sha256' : 'sha3-256').update(bytes).digest());
		},
		async stamp(options) {
			calls.push(options);
			return options.records.map((r, i) => ({
				format: 'qstamp-receipt/1',
				chain: { id: 'Q-test', genesis: '00' },
				contract: 'Qc',
				kind: String(options.kind ?? '0'),
				record: { alg: r.alg ?? 'sha3-256', digest: Buffer.from(r.digest).toString('hex'), salt: '00' },
				proof: { index: i, size: options.records.length, path: [] },
				root: '00',
				anchor: { tx: 'tx' + i, height: 1, block: 'b', time: 1, sender: 'Qs' },
			}));
		},
	};
}

const seed = new Uint8Array(32).fill(5);

test('wraps a handler and anchors each call with one record', async () => {
	const q = fakeQstamp();
	const receipts = [];
	const audit = new QstampToolAudit({ qstamp: q, seed, index: 0, kind: 7757, onReceipt: (r, n) => receipts.push([n, r.anchor.tx]) });
	const handler = audit.wrap('search', async (args) => ({ content: [{ type: 'text', text: 'result for ' + args.q }] }));
	const out = await handler({ q: 'hello' }, { http: {} });
	assert.deepEqual(out, { content: [{ type: 'text', text: 'result for hello' }] });
	assert.equal(q.calls.length, 1);
	assert.equal(q.calls[0].records.length, 1);
	assert.equal(receipts.length, 1);
	assert.equal(receipts[0][0], 'search');
});

test('only the digest leaves, raw args and result stay private', async () => {
	const q = fakeQstamp();
	const audit = new QstampToolAudit({ qstamp: q, seed, index: 0, project: (name, args, result) => ({ name, args, result }) });
	const handler = audit.wrap('secretTool', async () => ({ content: [{ type: 'text', text: 'TOP-SECRET-OUTPUT' }] }));
	await handler({ key: 'TOP-SECRET-INPUT' }, {});
	const blob = JSON.stringify(q.calls, (k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v));
	assert.ok(!blob.includes('TOP-SECRET-INPUT'), 'tool input must not reach the stamp call');
	assert.ok(!blob.includes('TOP-SECRET-OUTPUT'), 'tool output must not reach the stamp call');
	assert.equal(q.calls[0].records[0].digest.length, 32);
});

test('digest is deterministic and independent of key order', async () => {
	const q = fakeQstamp();
	const audit = new QstampToolAudit({ qstamp: q, seed, index: 0 });
	await audit.record('t', [], { a: 1, b: 2 });
	await audit.record('t', [], { b: 2, a: 1 });
	const [d0, d1] = q.calls.map((c) => Buffer.from(c.records[0].digest).toString('hex'));
	assert.equal(d0, d1);
});

test('a tool call still succeeds when anchoring fails', async () => {
	const q = fakeQstamp();
	q.stamp = async () => {
		throw new Error('chain unreachable');
	};
	const errors = [];
	const audit = new QstampToolAudit({ qstamp: q, seed, index: 0, onError: (e, n) => errors.push([n, String(e.message)]) });
	const handler = audit.wrap('t', async () => ({ content: [{ type: 'text', text: 'ok' }] }));
	const out = await handler({});
	assert.deepEqual(out, { content: [{ type: 'text', text: 'ok' }] }, 'result returns despite anchor failure');
	assert.equal(errors.length, 1);
	assert.equal(errors[0][0], 't');
});

test('a tool call still succeeds when anchoring fails and no onError is set', async () => {
	const q = fakeQstamp();
	q.stamp = async () => {
		throw new Error('chain unreachable');
	};
	const audit = new QstampToolAudit({ qstamp: q, seed, index: 0 });
	const handler = audit.wrap('t', async () => ({ content: [{ type: 'text', text: 'ok' }] }));
	const out = await handler({});
	assert.deepEqual(out, { content: [{ type: 'text', text: 'ok' }] });
});

test('passes handler arguments through unchanged', async () => {
	const q = fakeQstamp();
	const audit = new QstampToolAudit({ qstamp: q, seed, index: 0 });
	let seen;
	const handler = audit.wrap('t', async (args, ctx) => {
		seen = { args, ctx };
		return { content: [] };
	});
	await handler({ a: 1 }, { http: { authInfo: { scopes: [] } } });
	assert.deepEqual(seen.args, { a: 1 });
	assert.deepEqual(seen.ctx, { http: { authInfo: { scopes: [] } } });
});

test('rejects bad construction', () => {
	assert.throws(() => new QstampToolAudit({ qstamp: null, seed, index: 0 }));
	assert.throws(() => new QstampToolAudit({ qstamp: fakeQstamp(), seed: new Uint8Array(0), index: 0 }));
	assert.throws(() => new QstampToolAudit({ qstamp: fakeQstamp(), seed, index: -1 }));
});
