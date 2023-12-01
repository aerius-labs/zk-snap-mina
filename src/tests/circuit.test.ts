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
import { VoterCircuit, VoterState } from '../circuits/voter_circuit';
import { EncryptionPublicKey } from '../circuits/utils/paillier';

const generateVoterCircuitWitness = (
  proposalId: Field,
  userPrivKey: PrivateKey,
  encPubKey: paillierBigint.PublicKey,
  membersTree: MerkleTree,
  userIdx: bigint,
  vote: number
) => {
  const userSignature: Signature = Signature.create(userPrivKey, [proposalId]);

  const userVote = [];
  for (let i = 0; i < 5; i++) {
    if (i === vote) {
      userVote.push(Field(1n));
    } else {
      userVote.push(Field(0n));
    }
  }
  const r_enc = [];
  for (let i = 0; i < userVote.length; i++) {
    r_enc.push(Field(getRandomNBitNumber(63)));
  }
  let userEncVote = [];
  for (let i = 0; i < userVote.length; i++) {
    userEncVote.push(
      Field(encPubKey.encrypt(userVote[i].toBigInt(), r_enc[i].toBigInt()))
    );
  }

  const userPubKey = userPrivKey.toPublicKey();

  const userNullifierJson = Nullifier.createTestNullifier(
    [proposalId, userPubKey.x],
    userPrivKey
  );
  const userNullifier = Nullifier.fromJSON(userNullifierJson);

  const userInclusionProofWitness = membersTree.getWitness(userIdx);
  const userInclusionProof = new WhitelistMerkleWitness(
    userInclusionProofWitness
  );

  const membersRoot = membersTree.getRoot();

  const circuitEncPubKey = new EncryptionPublicKey({
    n: Field(encPubKey.n),
    g: Field(encPubKey.g),
    n_2: Field(encPubKey._n2),
  });

  const voterState = new VoterState({
    voterWhitelistRoot: membersRoot,
    proposalId: proposalId,
    encryptedVote: userEncVote,
    encryptionPubKey: circuitEncPubKey,
    voterNullifierKey: userNullifier.key(),
  });

  return {
    voterState,
    userVote,
    r_enc,
    userPubKey,
    userInclusionProof,
    userSignature,
    userNullifier,
  };
};

describe('Circuit Tests', () => {
  let cache: Cache;

  let encPrivKey: paillierBigint.PrivateKey;
  let encPubKey: paillierBigint.PublicKey;

  let circuitEncPubKey: EncryptionPublicKey;

  let user1PrivKey: PrivateKey;
  let user1PubKey: PublicKey;
  let user2PrivKey: PrivateKey;
  let user2PubKey: PublicKey;

  let proposalId: Field = Field.random();
  let membersTree: MerkleTree;
  let membersRoot: Field;

  const isCircuit = false;

  beforeAll(async () => {
    cache = Cache.FileSystem(
      '/Users/shreyaslondhe/Desktop/dev/aerius-repos/zk-snap/keys'
    );

    console.time('circuit compilation...');
    const { verificationKey } = await VoterCircuit.compile({ cache });
    console.timeEnd('circuit compilation...');

    [encPubKey, encPrivKey] = await generateEncryptionKeyPair(63);

    circuitEncPubKey = new EncryptionPublicKey({
      n: Field(encPubKey.n),
      g: Field(encPubKey.g),
      n_2: Field(encPubKey._n2),
    });

    user1PrivKey = PrivateKey.random();
    user1PubKey = user1PrivKey.toPublicKey();

    user2PrivKey = PrivateKey.random();
    user2PubKey = user2PrivKey.toPublicKey();

    membersTree = new MerkleTree(8);
    membersTree.setLeaf(0n, Poseidon.hash([user1PubKey.x]));
    membersTree.setLeaf(1n, Poseidon.hash([user2PubKey.x]));

    membersRoot = membersTree.getRoot();
  });

  it('should generate a user1 vote proof', async () => {
    const {
      voterState,
      userVote,
      r_enc,
      userPubKey,
      userInclusionProof,
      userSignature,
      userNullifier,
    } = generateVoterCircuitWitness(
      proposalId,
      user1PrivKey,
      encPubKey,
      membersTree,
      0n,
      1
    );

    console.time('proof generation...');
    const proof = await VoterCircuit.generateProof(
      voterState,
      userVote,
      r_enc,
      userPubKey,
      userInclusionProof,
      userSignature,
      userNullifier
    );
    console.timeEnd('proof generation...');

    console.time('proof verification...');
    const ok = await VoterCircuit.verify(proof);
    console.timeEnd('proof verification...');

    expect(ok).toBeTruthy();
  });

  it('should generate a user2 vote proof', async () => {
    const {
      voterState,
      userVote,
      r_enc,
      userPubKey,
      userInclusionProof,
      userSignature,
      userNullifier,
    } = generateVoterCircuitWitness(
      proposalId,
      user2PrivKey,
      encPubKey,
      membersTree,
      1n,
      2
    );

    console.time('proof generation...');
    const proof = await VoterCircuit.generateProof(
      voterState,
      userVote,
      r_enc,
      userPubKey,
      userInclusionProof,
      userSignature,
      userNullifier
    );
    console.timeEnd('proof generation...');

    console.time('proof verification...');
    const ok = await VoterCircuit.verify(proof);
    console.timeEnd('proof verification...');

    expect(ok).toBeTruthy();
  });
});
