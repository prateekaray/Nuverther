import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { normalizeFieldHex, destroyBarretenberg } from '@nuverther/zk';
import {
  decryptWalletKeystore,
  encryptWalletKeystore,
  generateWallet,
  recoverWalletFromShamirShares,
  splitMasterSeedShamir,
  type EncryptedKeystore,
} from './custody.ts';
import {
  SpendIntentStore,
} from './intentStore.ts';
import {
  discoverEpochDirectory,
  discoverVerifiedPeers,
  executeShieldedSpend,
  recoverEncryptedThreadFromShards,
  recoverSpendIntent,
} from './transport.ts';

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);

  if (command === 'keygen') {
    const { values } = parseArgs({
      args: rest,
      options: {
        out: { type: 'string', default: 'nuverther-wallet.json' },
        passphrase: { type: 'string' },
      },
    });
    const passphrase = values.passphrase ?? process.env.NUVERTHER_PASSPHRASE;
    if (!passphrase) {
      throw new Error('Provide --passphrase or NUVERTHER_PASSPHRASE');
    }
    const keys = await generateWallet();
    const keystore = await encryptWalletKeystore(keys, passphrase);
    writeFileSync(values.out, JSON.stringify(keystore, null, 2), 'utf8');
    console.log(
      JSON.stringify({
        created: values.out,
        ownerPkHex: keys.ownerPkHex,
        ed25519PkHex: keys.ed25519PkHex,
      }),
    );
    return;
  }

  if (command === 'split-key') {
    const { values } = parseArgs({
      args: rest,
      options: {
        wallet: { type: 'string', default: 'nuverther-wallet.json' },
        passphrase: { type: 'string' },
        total: { type: 'string', default: '3' },
        threshold: { type: 'string', default: '2' },
      },
    });
    const passphrase = values.passphrase ?? process.env.NUVERTHER_PASSPHRASE;
    if (!passphrase) throw new Error('Provide --passphrase or NUVERTHER_PASSPHRASE');
    const keystore = JSON.parse(readFileSync(values.wallet, 'utf8')) as EncryptedKeystore;
    const keys = await decryptWalletKeystore(keystore, passphrase);
    const shares = await splitMasterSeedShamir(
      keys.masterSeed,
      Number(values.total),
      Number(values.threshold),
    );
    console.log(JSON.stringify({ threshold: Number(values.threshold), total: Number(values.total), shares }, null, 2));
    return;
  }

  if (command === 'recover-key') {
    const { values } = parseArgs({
      args: rest,
      options: {
        shares: { type: 'string' },
        out: { type: 'string', default: 'nuverther-recovered.json' },
        passphrase: { type: 'string' },
      },
    });
    const passphrase = values.passphrase ?? process.env.NUVERTHER_PASSPHRASE;
    if (!values.shares || !passphrase) {
      throw new Error('Provide --shares comma-separated and --passphrase');
    }
    const keys = await recoverWalletFromShamirShares(values.shares.split(',').map((s) => s.trim()));
    const keystore = await encryptWalletKeystore(keys, passphrase);
    writeFileSync(values.out, JSON.stringify(keystore, null, 2), 'utf8');
    console.log(JSON.stringify({ recovered: values.out, ownerPkHex: keys.ownerPkHex }));
    return;
  }

  if (command === 'peers') {
    const { values } = parseArgs({
      args: rest,
      options: {
        seeds: { type: 'string', default: 'http://127.0.0.1:4101' },
      },
    });
    const { directory } = await discoverEpochDirectory(values.seeds.split(',').map((s) => s.trim()));
    console.log(
      JSON.stringify(
        {
          epoch: directory.epoch,
          quorumSize: directory.quorumSize,
          count: directory.members.length,
          peers: directory.members.map((p) => ({ peerId: p.peerId, endpoint: p.endpoint })),
        },
        null,
        2,
      ),
    );
    return;
  }

  if (command === 'supply') {
    const { values } = parseArgs({
      args: rest,
      options: {
        seeds: { type: 'string', default: 'http://127.0.0.1:4101' },
      },
    });
    const seed = values.seeds.split(',')[0]!.trim();
    const res = await fetch(`${seed}/v1/issuance`);
    console.log(await res.text());
    return;
  }

  if (command === 'spend') {
    const { values } = parseArgs({
      args: rest,
      options: {
        wallet: { type: 'string', default: 'nuverther-wallet.json' },
        passphrase: { type: 'string' },
        seeds: { type: 'string', default: 'http://127.0.0.1:4101' },
        intentFile: { type: 'string', default: 'nuverther-intents.json' },
        in0: { type: 'string', default: '1000' },
        in1: { type: 'string', default: '500' },
        leaf0: { type: 'string', default: '0' },
        leaf1: { type: 'string', default: '1' },
        blind0: { type: 'string' },
        blind1: { type: 'string' },
        out0: { type: 'string', default: '1200' },
        out1: { type: 'string', default: '290' },
        fee: { type: 'string', default: '10' },
        recipient: { type: 'string' },
      },
    });
    const passphrase = values.passphrase ?? process.env.NUVERTHER_PASSPHRASE;
    if (!passphrase) throw new Error('Provide --passphrase or NUVERTHER_PASSPHRASE');
    if (!values.blind0 || !values.blind1) {
      throw new Error('Provide --blind0 and --blind1 field elements for input notes');
    }
    const keystore = JSON.parse(readFileSync(values.wallet, 'utf8')) as EncryptedKeystore;
    const keys = await decryptWalletKeystore(keystore, passphrase);
    const { directory } = await discoverEpochDirectory(values.seeds.split(',').map((s) => s.trim()));
    const peers = directory.members;
    const recipientPk = values.recipient ? BigInt(values.recipient) : keys.ownerPk;
    const intentStore = new SpendIntentStore(values.intentFile);

    const result = await executeShieldedSpend({
      keys,
      directory,
      intentStore,
      inputs: [
        { amount: BigInt(values.in0), blinding: BigInt(values.blind0), leafIndex: Number(values.leaf0) },
        { amount: BigInt(values.in1), blinding: BigInt(values.blind1), leafIndex: Number(values.leaf1) },
      ],
      outputs: [
        { amount: BigInt(values.out0), recipientOwnerPk: recipientPk },
        { amount: BigInt(values.out1), recipientOwnerPk: keys.ownerPk },
      ],
      fee: BigInt(values.fee),
    });

    const recoveredThread = await recoverEncryptedThreadFromShards({
      peers,
      shardPointers: result.shardPointers.slice(0, 2),
      threadKeyHex: result.threadKeyHex,
    });

    console.log(
      JSON.stringify(
        {
          epoch: result.epoch,
          nullifiers: result.proofBundle.publicSignals.nullifiers,
          quorumWitnesses: result.quorumWitnesses,
          attestationsVerified: result.attestations.length,
          outputLeafIndices: result.outputLeafIndices,
          newMerkleRoot: result.newMerkleRoot,
          threadDigest: result.threadDigest,
          recoveredThreadAmount: recoveredThread.amount,
          txBinding: normalizeFieldHex(result.proofBundle.publicSignals.txBinding),
        },
        null,
        2,
      ),
    );
    return;
  }

  if (command === 'recover-intents') {
    const { values } = parseArgs({
      args: rest,
      options: {
        wallet: { type: 'string', default: 'nuverther-wallet.json' },
        passphrase: { type: 'string' },
        seeds: { type: 'string', default: 'http://127.0.0.1:4101' },
        intentFile: { type: 'string', default: 'nuverther-intents.json' },
      },
    });
    const passphrase = values.passphrase ?? process.env.NUVERTHER_PASSPHRASE;
    if (!passphrase) throw new Error('Provide --passphrase or NUVERTHER_PASSPHRASE');
    const keystore = JSON.parse(readFileSync(values.wallet, 'utf8')) as EncryptedKeystore;
    const keys = await decryptWalletKeystore(keystore, passphrase);
    const { directory } = await discoverEpochDirectory(values.seeds.split(',').map((s) => s.trim()));
    const peers = await discoverVerifiedPeers(values.seeds.split(',').map((s) => s.trim()));
    const intentStore = new SpendIntentStore(values.intentFile);
    const pending = intentStore.listIncomplete();
    const outcomes = [];
    for (const item of pending) {
      outcomes.push(
        await recoverSpendIntent({
          intentStore,
          txBinding: item.txBinding,
          keys,
          peers,
          directory,
        }),
      );
    }
    console.log(JSON.stringify({ recoveredCount: outcomes.length, outcomes }, null, 2));
    return;
  }

  console.error('Usage: nuverther <keygen|split-key|recover-key|peers|supply|spend|recover-intents> [options]');
  process.exit(1);
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await destroyBarretenberg();
  });
