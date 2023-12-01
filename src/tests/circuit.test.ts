import {
  Cache,
  Field,
  MerkleMap,
  MerkleTree,
  Nullifier,
  Poseidon,
  PrivateKey,
  PublicKey,
  SelfProof,
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
import {
  AggregatorCircuit,
  AggregatorState,
} from '../circuits/aggregator_circuit';
import { setNullifierUsed } from '../circuits/vote_validation/vote_validation';

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
  let voterCircuitCache: Cache;
  let aggregatorCircuitCache: Cache;

  let encPrivKey: paillierBigint.PrivateKey;
  let encPubKey: paillierBigint.PublicKey;

  let circuitEncPubKey: EncryptionPublicKey;

  let user1PrivKey: PrivateKey;
  let user1PubKey: PublicKey;
  let user2PrivKey: PrivateKey;
  let user2PubKey: PublicKey;

  let user1EncVotes: Field[];
  let user2EncVotes: Field[];

  let user1NullifierKey: Field;
  let user2NullifierKey: Field;

  let proposalId: Field = Field.random();
  let membersTree: MerkleTree;
  let membersRoot: Field;

  let nullifierTree: MerkleMap;
  let nullifierRoot: Field;

  let earlierProof: SelfProof<AggregatorState, void>;
  let voterProof: SelfProof<VoterState, void>;

  beforeAll(async () => {
    voterCircuitCache = Cache.FileSystem(
      '/Users/shreyaslondhe/Desktop/dev/aerius-repos/zk-snap/keys/voter_circuit'
    );
    aggregatorCircuitCache = Cache.FileSystem(
      '/Users/shreyaslondhe/Desktop/dev/aerius-repos/zk-snap/keys/aggregator_circuit'
    );

    console.time('voter circuit compilation...');
    await VoterCircuit.compile({
      cache: voterCircuitCache,
    });
    console.timeEnd('voter circuit compilation...');

    console.time('aggregator circuit compilation...');
    await AggregatorCircuit.compile({
      cache: aggregatorCircuitCache,
    });
    console.timeEnd('aggregator circuit compilation...');

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

    nullifierTree = new MerkleMap();
    nullifierRoot = nullifierTree.getRoot();
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
      1 // vote for 2nd option
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

    voterProof = proof;
    user1EncVotes = voterState.encryptedVote;
    user1NullifierKey = voterState.voterNullifierKey;

    expect(ok).toBeTruthy();
  });

  it('should generate base proof for current proposal', async () => {
    const oldVoteCount = [];
    for (let i = 0; i < 5; i++) {
      oldVoteCount.push(Field(encPubKey.encrypt(0n)));
    }
    const newVoteCount = oldVoteCount;

    const aggregatorState = new AggregatorState({
      encryptionPubKey: circuitEncPubKey,
      proposalId: proposalId,
      voterWhitelistRoot: membersRoot,
      oldNullifierRoot: nullifierRoot,
      newNullifierRoot: nullifierRoot,
      oldVoteCount: oldVoteCount,
      newVoteCount: newVoteCount,
    });

    console.time('base proof generation...');
    const proof = await AggregatorCircuit.generateBaseProof(aggregatorState);
    console.timeEnd('base proof generation...');

    console.time('base proof verification...');
    const ok = await AggregatorCircuit.verify(proof);
    console.timeEnd('base proof verification...');

    earlierProof = proof;

    expect(ok).toBeTruthy();
  });

  it("should aggregate user1's vote", async () => {
    const voterNullifierWitness = nullifierTree.getWitness(user1NullifierKey);
    nullifierTree.set(user1NullifierKey, Field(1n));

    const newNullifierRoot = setNullifierUsed(
      user1NullifierKey,
      voterNullifierWitness
    );

    const newVoteCount = [];
    for (let i = 0; i < 5; i++) {
      newVoteCount.push(
        Field(
          encPubKey.addition(
            earlierProof.publicInput.newVoteCount[i].toBigInt(),
            user1EncVotes[i].toBigInt()
          )
        )
      );
    }

    const aggregatorState = new AggregatorState({
      encryptionPubKey: circuitEncPubKey,
      proposalId: proposalId,
      voterWhitelistRoot: membersRoot,
      oldNullifierRoot: nullifierRoot,
      newNullifierRoot: newNullifierRoot,
      oldVoteCount: earlierProof.publicInput.oldVoteCount,
      newVoteCount: newVoteCount,
    });

    console.time('recursive proof generation...');
    const proof = await AggregatorCircuit.generateRecursiveProof(
      aggregatorState,
      earlierProof,
      voterProof,
      voterNullifierWitness
    );
    console.timeEnd('recursive proof generation...');

    console.time('recursive proof verification...');
    const ok = await AggregatorCircuit.verify(proof);
    console.timeEnd('recursive proof verification...');

    earlierProof = proof;
    nullifierRoot = newNullifierRoot;

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
      2 // vote for 3rd option
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

    voterProof = proof;
    user2EncVotes = voterState.encryptedVote;
    user2NullifierKey = voterState.voterNullifierKey;

    expect(ok).toBeTruthy();
  });

  it("should aggregate user2's vote", async () => {
    const voterNullifierWitness = nullifierTree.getWitness(user2NullifierKey);
    nullifierTree.set(user2NullifierKey, Field(1n));

    const newNullifierRoot = setNullifierUsed(
      user2NullifierKey,
      voterNullifierWitness
    );

    const newVoteCount = [];
    for (let i = 0; i < 5; i++) {
      newVoteCount.push(
        Field(
          encPubKey.addition(
            earlierProof.publicInput.newVoteCount[i].toBigInt(),
            user2EncVotes[i].toBigInt()
          )
        )
      );
    }

    const aggregatorState = new AggregatorState({
      encryptionPubKey: circuitEncPubKey,
      proposalId: proposalId,
      voterWhitelistRoot: membersRoot,
      oldNullifierRoot: nullifierRoot,
      newNullifierRoot: newNullifierRoot,
      oldVoteCount: earlierProof.publicInput.newVoteCount,
      newVoteCount: newVoteCount,
    });

    console.time('recursive proof generation...');
    const proof = await AggregatorCircuit.generateRecursiveProof(
      aggregatorState,
      earlierProof,
      voterProof,
      voterNullifierWitness
    );
    console.timeEnd('recursive proof generation...');

    console.time('recursive proof verification...');
    const ok = await AggregatorCircuit.verify(proof);
    console.timeEnd('recursive proof verification...');

    earlierProof = proof;
    nullifierRoot = newNullifierRoot;

    expect(ok).toBeTruthy();

    const decryptedVote = [];
    for (let i = 0; i < 5; i++) {
      decryptedVote.push(
        encPrivKey.decrypt(earlierProof.publicInput.newVoteCount[i].toBigInt())
      );
    }
    expect(decryptedVote).toEqual([0n, 1n, 1n, 0n, 0n]);
  });
});
