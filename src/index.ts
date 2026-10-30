// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import type { DigestAlgorithm, QstampModule, Receipt } from './types.js';

export type { DigestAlgorithm, QstampModule, Receipt, StampOptions, StampRecord } from './types.js';

export interface QstampToolAuditOptions {
	qstamp: QstampModule;
	seed: Uint8Array;
	index: number;
	kind?: string | number | bigint;
	rpc?: string | string[];
	digestAlg?: DigestAlgorithm;
	project?: (name: string, args: unknown[], result: unknown) => unknown;
	onReceipt?: (receipt: Receipt, name: string) => void;
	onError?: (error: unknown, name: string) => void;
}

function stableStringify(value: unknown): string {
	if (value === null || typeof value !== 'object') {
		return JSON.stringify(value) ?? 'null';
	}
	if (Array.isArray(value)) {
		return '[' + value.map(stableStringify).join(',') + ']';
	}
	const obj = value as Record<string, unknown>;
	const entries = Object.keys(obj)
		.sort()
		.map((key) => JSON.stringify(key) + ':' + stableStringify(obj[key]));
	return '{' + entries.join(',') + '}';
}

function defaultProjection(name: string, _args: unknown[], result: unknown): unknown {
	return { tool: name, result };
}

// A tool handler registered with the MCP SDK. It takes the parsed arguments and
// the server context, or just the context when the tool has no arguments, and
// returns a result or a promise of one.
export type ToolHandler = (...args: never[]) => unknown;

/**
 * QstampToolAudit anchors MCP tool calls on chain. It wraps a tool handler so
 * each invocation is fingerprinted and signed into a Qstamp receipt once the
 * handler returns. Only the digest leaves the process, so the arguments and the
 * result stay with the server while the proof that the call happened in one
 * exact form at a point in time is anchored on the Quantova network.
 *
 * Anchoring never breaks a tool. A failure to stamp is routed to the onError
 * callback and the handler result is returned unchanged.
 */
export class QstampToolAudit {
	readonly #options: QstampToolAuditOptions;
	readonly #alg: DigestAlgorithm;

	constructor(options: QstampToolAuditOptions) {
		if (!options || typeof options.qstamp !== 'object' || options.qstamp === null) {
			throw new Error('a qstamp module is required');
		}
		if (!(options.seed instanceof Uint8Array) || options.seed.length === 0) {
			throw new Error('a signing seed is required');
		}
		if (!Number.isInteger(options.index) || options.index < 0) {
			throw new Error('a whole account index is required');
		}
		this.#options = options;
		this.#alg = options.digestAlg ?? 'sha3-256';
	}

	// wrap returns a handler with the same call signature as the one passed in.
	// The returned handler runs the original, anchors the call, and returns the
	// original result.
	wrap<H extends ToolHandler>(name: string, handler: H): H {
		const run = async (...args: never[]): Promise<unknown> => {
			const result = await handler(...args);
			try {
				await this.record(name, args as unknown[], result);
			} catch {
				// An audit layer must never break the tool it wraps. Pass onError
				// to observe anchoring failures.
			}
			return result;
		};
		return run as unknown as H;
	}

	// record anchors a single tool call. It is called by wrap, and is also
	// available for servers that drive the handler themselves.
	async record(name: string, args: unknown[], result: unknown): Promise<Receipt | undefined> {
		try {
			const project = this.#options.project ?? defaultProjection;
			const canonical = stableStringify(project(name, args, result));
			const digest = this.#options.qstamp.digestBytes(new TextEncoder().encode(canonical), this.#alg);
			const receipts = await this.#options.qstamp.stamp({
				seed: this.#options.seed,
				index: this.#options.index,
				records: [{ digest: Uint8Array.from(digest), alg: this.#alg }],
				...(this.#options.kind !== undefined ? { kind: this.#options.kind } : {}),
				...(this.#options.rpc !== undefined ? { rpc: this.#options.rpc } : {}),
			});
			const receipt = receipts[0];
			if (receipt) {
				this.#options.onReceipt?.(receipt, name);
			}
			return receipt;
		} catch (error) {
			if (this.#options.onError) {
				this.#options.onError(error, name);
				return undefined;
			}
			throw error;
		}
	}
}

export default QstampToolAudit;
