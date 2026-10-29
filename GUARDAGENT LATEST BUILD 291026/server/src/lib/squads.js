// Squads v4 smart accounts: PDA derivation, multisig_create_v2 instruction, and decoders for multisig and
// vault-transaction accounts. Written against the Squads v4 on-chain layout; no SDK needed.
import { findProgramAddress, anchorDisc, toBytes, b58encode, PROGRAMS, u32le, u16le } from './solana.js';

const PID = PROGRAMS.SQUADS_V4;
const S = s => Buffer.from(s);
export const programConfigPda = () => findProgramAddress([S('multisig'), S('program_config')], PID)[0];
export const multisigPda = createKey => findProgramAddress([S('multisig'), S('multisig'), toBytes(createKey)], PID)[0];
export const vaultPda = (multisig, index = 0) => findProgramAddress([S('multisig'), toBytes(multisig), S('vault'), Buffer.from([index])], PID)[0];
export const PERM = { initiate: 1, vote: 2, execute: 4, all: 7 };

const optPubkey = k => (k ? Buffer.concat([Buffer.from([1]), Buffer.from(toBytes(k))]) : Buffer.from([0]));
const optString = s => (s ? Buffer.concat([Buffer.from([1]), u32le(Buffer.byteLength(s)), Buffer.from(s)]) : Buffer.from([0]));

export function multisigCreateV2Ix({ treasury, createKey, creator, threshold, members, timeLock = 0, configAuthority = null, rentCollector = null, memo = null }) {
  const multisig = multisigPda(createKey);
  const data = Buffer.concat([
    anchorDisc('multisig_create_v2'), optPubkey(configAuthority), u16le(threshold), u32le(members.length),
    ...members.map(m => Buffer.concat([Buffer.from(toBytes(m.key)), Buffer.from([m.permissions ?? PERM.all])])),
    u32le(timeLock), optPubkey(rentCollector), optString(memo)
  ]);
  return {
    multisig,
    ix: { programId: PID, data, keys: [
      { pubkey: programConfigPda(), isSigner: false, isWritable: false },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: multisig, isSigner: false, isWritable: true },
      { pubkey: createKey, isSigner: true, isWritable: false },
      { pubkey: creator, isSigner: true, isWritable: true },
      { pubkey: PROGRAMS.SYSTEM, isSigner: false, isWritable: false }
    ] }
  };
}

export function decodeProgramConfig(b64) {
  const d = Buffer.from(b64, 'base64');
  return { authority: b58encode(d.subarray(8, 40)), creationFee: d.readBigUInt64LE(40), treasury: b58encode(d.subarray(48, 80)) };
}

export function decodeMultisig(b64) {
  const d = Buffer.from(b64, 'base64');
  let o = 8;
  const createKey = b58encode(d.subarray(o, o + 32)); o += 32;
  const configAuthority = b58encode(d.subarray(o, o + 32)); o += 32;
  const threshold = d.readUInt16LE(o); o += 2;
  const timeLock = d.readUInt32LE(o); o += 4;
  const transactionIndex = d.readBigUInt64LE(o); o += 8;
  const staleIndex = d.readBigUInt64LE(o); o += 8;
  const hasRent = d[o]; o += 1; if (hasRent) o += 32;
  o += 1; // bump
  const n = d.readUInt32LE(o); o += 4;
  const members = [];
  for (let i = 0; i < n; i++) { members.push({ key: b58encode(d.subarray(o, o + 32)), permissions: d[o + 32] }); o += 33; }
  return { createKey, configAuthority, threshold, timeLock, transactionIndex, staleIndex, members };
}

export function decodeVaultTransaction(b64) {
  const d = Buffer.from(b64, 'base64');
  let o = 8;
  const multisig = b58encode(d.subarray(o, o + 32)); o += 32;
  const creator = b58encode(d.subarray(o, o + 32)); o += 32;
  const index = d.readBigUInt64LE(o); o += 8;
  o += 1; // bump
  const vaultIndex = d[o]; o += 2; // vault_index + vault_bump
  const nEph = d.readUInt32LE(o); o += 4 + nEph;
  const numSigners = d[o], numWritableSigners = d[o + 1], numWritableNonSigners = d[o + 2]; o += 3;
  const nKeys = d.readUInt32LE(o); o += 4;
  const keys = [];
  for (let i = 0; i < nKeys; i++) { keys.push(b58encode(d.subarray(o, o + 32))); o += 32; }
  const nIx = d.readUInt32LE(o); o += 4;
  const instructions = [];
  for (let i = 0; i < nIx; i++) {
    const programIdIndex = d[o]; o += 1;
    const na = d.readUInt32LE(o); o += 4; const accounts = [...d.subarray(o, o + na)]; o += na;
    const nd = d.readUInt32LE(o); o += 4; const data = d.subarray(o, o + nd); o += nd;
    instructions.push({ programId: keys[programIdIndex], accounts: accounts.map(a => keys[a]), data });
  }
  return { multisig, creator, index, vaultIndex, numSigners, numWritableSigners, numWritableNonSigners, keys, instructions };
}

// Names for the Squads instructions we report on, keyed by Anchor discriminator.
export const SQUADS_IX = Object.fromEntries(['multisig_create', 'multisig_create_v2', 'multisig_add_member', 'multisig_remove_member', 'multisig_change_threshold', 'multisig_set_time_lock',
  'multisig_set_config_authority', 'multisig_add_spending_limit', 'multisig_remove_spending_limit', 'config_transaction_create', 'config_transaction_execute', 'vault_transaction_create',
  'vault_transaction_execute', 'batch_create', 'batch_add_transaction', 'batch_execute_transaction', 'proposal_create', 'proposal_activate', 'proposal_approve', 'proposal_reject',
  'proposal_cancel', 'spending_limit_use'].map(n => [anchorDisc(n).toString('hex'), n]));
