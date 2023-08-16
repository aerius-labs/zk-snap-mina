import {
  Field,
  MerkleMap,
  MerkleTree,
  Nullifier,
  Poseidon,
  PrivateKey,
  Proof,
  PublicKey,
  Signature,
  verify,
} from 'snarkyjs';
import {
  MyMerkleWitness,
  UserCircuit,
  UserState,
} from '../circuits/UserCircuit';
import {
  AggregatorCircuit,
  AggregatorState,
} from '../circuits/AggregatorCircuit';

describe('Aggregator Circuit Test', () => {
  let userCircuitVK: string;
  let aggregatorCircuitVK: string;

  let encryptionPrivateKey: PrivateKey;
  let encryptionPublicKey: PublicKey;

  let userPrivateKey: PrivateKey;
  let userPublicKey: PublicKey;

  let electionID = Field(1);
  let nonce = Field(0);

  let nullifierTree: MerkleMap;
  let oldNullifierRoot: Field;
  let newNullifierRoot: Field;

  let voterTree: MerkleTree;
  let voterRoot: Field;

  let userProof: Proof<UserState, void>;

  let aggregatorBaseProof: Proof<AggregatorState, void>;
  let aggregatorState: AggregatorState;

  beforeAll(async () => {
    encryptionPrivateKey = PrivateKey.random();
    encryptionPublicKey = PublicKey.fromPrivateKey(encryptionPrivateKey);

    userPrivateKey = PrivateKey.random();
    userPublicKey = PublicKey.fromPrivateKey(userPrivateKey);

    voterTree = new MerkleTree(8);

    nullifierTree = new MerkleMap();
    oldNullifierRoot = nullifierTree.getRoot();
    newNullifierRoot = oldNullifierRoot;

    const { verificationKey: vk1 } = await UserCircuit.compile();
    userCircuitVK = vk1;
    const { verificationKey: vk2 } = await AggregatorCircuit.compile();
    aggregatorCircuitVK = vk2;
  });

  it('should generate an User Proof', async () => {
    const userSignature: Signature = Signature.create(userPrivateKey, [
      userPublicKey.x,
      electionID,
    ]);

    const vote: Field = Field(1);
    const voteWeight: Field = Field(50);

    const salt: Field = Field.random();

    const userBalance: Field = Field(100);

    const jsonNullifier = Nullifier.createTestNullifier(
      [userPublicKey.x, electionID],
      userPrivateKey
    );
    const nullifier = Nullifier.fromJSON(jsonNullifier);

    newNullifierRoot = nullifier.setUsed(
      nullifierTree.getWitness(nullifier.key())
    );

    voterTree.setLeaf(0n, Poseidon.hash([userPublicKey.x, userBalance]));
    voterTree.setLeaf(1n, Field.random());
    voterTree.setLeaf(2n, Field.random());
    voterTree.setLeaf(3n, Field.random());

    voterRoot = voterTree.getRoot();

    const merkleWitness = voterTree.getWitness(0n);
    const merkleProof = new MyMerkleWitness(merkleWitness);

    const userState = UserState.create(
      nullifier,
      encryptionPublicKey,
      voterRoot,
      userPublicKey,
      electionID
    );

    userProof = await UserCircuit.generateProof(
      userState,
      userSignature,
      vote,
      voteWeight,
      salt,
      userBalance,
      merkleProof
    );

    const result = await verify(userProof, userCircuitVK);
    expect(result).toBe(true);
  });

  it('should generate an Aggregator Base Proof', async () => {
    aggregatorState = AggregatorState.create(
      encryptionPublicKey,
      electionID,
      voterRoot,
      oldNullifierRoot,
      newNullifierRoot,
      nonce
    );

    aggregatorBaseProof = await AggregatorCircuit.generateBaseProof(
      aggregatorState
    );

    const result = await verify(aggregatorBaseProof, aggregatorCircuitVK);
    expect(result).toBe(true);

    nonce = nonce.add(Field(1));
  });

  it('should generate an Aggregator Proof', async () => {
    const nullifierWitness = nullifierTree.getWitness(
      userProof.publicInput.nullifier.key()
    );

    aggregatorState = AggregatorState.create(
      encryptionPublicKey,
      electionID,
      voterRoot,
      oldNullifierRoot,
      newNullifierRoot,
      nonce
    );

    const aggregatorProof = await AggregatorCircuit.generateProof(
      aggregatorState,
      aggregatorBaseProof,
      userProof,
      nullifierWitness
    );

    const result = await verify(aggregatorProof, aggregatorCircuitVK);
    expect(result).toBe(true);

    oldNullifierRoot = newNullifierRoot;
    nonce = nonce.add(Field(1));
  });
});
