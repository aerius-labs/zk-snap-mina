import {
  Cache,
  Field,
  MerkleTree,
  Nullifier,
  Poseidon,
  PrivateKey,
  PublicKey,
  Signature,
} from 'o1js';
import * as paillierBigint from 'paillier-bigint';
import {
  generateEncryptionKeyPair,
  getRandomNBitNumber,
} from '../utils/encryption_utils';
import { WhitelistMerkleWitness } from '../circuits/voting_strategies/whitelist';
import { UserCircuit, UserState } from '../circuits/voter_circuit';
import { EncryptionPublicKey } from '../circuits/utils/paillier';

describe('User Circuit Tests', () => {
  let cache: Cache;

  let encPrivKey: paillierBigint.PrivateKey;
  let encPubKey: paillierBigint.PublicKey;

  let circuitEncPubKey: EncryptionPublicKey;

  let userPrivKey: PrivateKey;
  let userPubKey: PublicKey;

  let proposalId: Field = Field.random();
  let membersTree: MerkleTree;
  let membersRoot: Field;

  const isCircuit = false;

  beforeAll(async () => {
    cache = Cache.FileSystem(
      '/Users/shreyaslondhe/Desktop/dev/aerius-repos/zk-snap/keys'
    );

    [encPubKey, encPrivKey] = await generateEncryptionKeyPair(63);

    circuitEncPubKey = new EncryptionPublicKey({
      n: Field(encPubKey.n),
      g: Field(encPubKey.g),
      n_2: Field(encPubKey._n2),
    });

    userPrivKey = PrivateKey.random();
    userPubKey = userPrivKey.toPublicKey();

    membersTree = new MerkleTree(8);
    membersTree.setLeaf(0n, Poseidon.hash([userPubKey.x]));

    membersRoot = membersTree.getRoot();
  });

  it('should generate a user vote proof', async () => {
    const userSignature: Signature = Signature.create(userPrivKey, [
      proposalId,
    ]);

    const userVote = [Field(0), Field(1), Field(0)];
    const r_enc: Field = Field(getRandomNBitNumber(63));
    let userEncVote = [];
    for (let i = 0; i < userVote.length; i++) {
      userEncVote.push(
        Field(encPubKey.encrypt(userVote[i].toBigInt(), r_enc.toBigInt()))
      );
    }

    const userNullifierJson = Nullifier.createTestNullifier(
      [proposalId, userPubKey.x],
      userPrivKey
    );
    const userNullifier = Nullifier.fromJSON(userNullifierJson);

    const userInclusionProofWitness = membersTree.getWitness(0n);
    const userInclusionProof = new WhitelistMerkleWitness(
      userInclusionProofWitness
    );

    const userState = new UserState({
      voterWhitelistRoot: membersRoot,
      proposalId: proposalId,
      encryptedVote: userEncVote,
      encryptionPubKey: circuitEncPubKey,
      voterNullifierKey: userNullifier.key(),
    });

    console.time('circuit compilation...');
    const { verificationKey } = await UserCircuit.compile({ cache });
    console.timeEnd('circuit compilation...');

    console.time('proof generation...');
    const proof = await UserCircuit.generateProof(
      userState,
      userVote,
      r_enc,
      userPubKey,
      userInclusionProof,
      userSignature,
      userNullifier
    );
    console.timeEnd('proof generation...');

    console.time('proof verification...');
    const ok = await UserCircuit.verify(proof);
    console.timeEnd('proof verification...');

    expect(ok).toBeTruthy();
  });
});
