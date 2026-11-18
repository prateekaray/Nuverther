import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { randomFieldElement, normalizeFieldHex, destroyBarretenberg } from '@nuverther/zk';
import {
  decryptWalletKeystore,
  encryptWalletKeystore,
  generateWallet,
  recoverWalletFromShamirShares,
  splitMasterSeedShamir,
  type EncryptedKeystore,
} from './custody.ts';
import {
  discoverVerifiedPeers,
  executeShieldedSpend,
  recoverEncryptedThreadFromShards,
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
    const peers = await discoverVerifiedPeers(values.seeds.split(',').map((s) => s.trim()));
    console.log(JSON.stringify({ count: peers.length, peers: peers.map((p) => ({ peerId: p.peerId, endpoint: p.endpoint })) }, null, 2));
    return;
  }

  if (command === 'spend') {
    const { values } = parseArgs({
      args: rest,
      options: {
        wallet: { type: 'string', default: 'nuverther-wallet.json' },
        passphrase: { type: 'string' },
        seeds: { type: 'string', default: 'http://127.0.0.1:4101' },
        in0: { type: 'string', default: '1000' },
        in1: { type: 'string', default: '500' },
        out0: { type: 'string', default: '1200' },
        out1: { type: 'string', default: '290' },
        fee: { type: 'string', default: '10' },
        recipient: { type: 'string' },
      },
    });
    const passphrase = values.passphrase ?? process.env.NUVERTHER_PASSPHRASE;
    if (!passphrase) throw new Error('Provide --passphrase or NUVERTHER_PASSPHRASE');
    const keystore = JSON.parse(readFileSync(values.wallet, 'utf8')) as EncryptedKeystore;
    const keys = await decryptWalletKeystore(keystore, passphrase);
    const peers = await discoverVerifiedPeers(values.seeds.split(',').map((s) => s.trim()));
    const recipientPk = values.recipient ? BigInt(values.recipient) : keys.ownerPk;

    const result = await executeShieldedSpend({
      keys,
      peers,
      inputs: [
        { amount: BigInt(values.in0), blinding: randomFieldElement(), threadId: randomFieldElement() },
        { amount: BigInt(values.in1), blinding: randomFieldElement(), threadId: randomFieldElement() },
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
          nullifiers: result.proofBundle.publicSignals.nullifiers,
          quorumWitnesses: result.quorumWitnesses,
          attestationsVerified: result.attestations.length,
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

  console.error('Usage: nuverther <keygen|split-key|recover-key|peers|spend> [options]');
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
