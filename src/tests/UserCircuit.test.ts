import * as fs from 'fs';
import * as path from 'path';
import {
  Field,
  MerkleTree,
  Nullifier,
  Poseidon,
  PrivateKey,
  PublicKey,
  Signature,
  verify,
} from 'snarkyjs';
import {
  MyMerkleWitness,
  UserCircuit,
  UserState,
} from '../circuits/UserCircuit';

const __dirname = path.resolve();

describe('User Circuit Test', () => {
  let encryptionPrivateKey: PrivateKey;
  let encryptionPublicKey: PublicKey;

  let userPrivateKey: PrivateKey;
  let userPublicKey: PublicKey;

  let electionID = Field(1);

  beforeAll(async () => {
    encryptionPrivateKey = PrivateKey.random();
    encryptionPublicKey = PublicKey.fromPrivateKey(encryptionPrivateKey);

    userPrivateKey = PrivateKey.random();
    userPublicKey = PublicKey.fromPrivateKey(userPrivateKey);
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

    // Construct Merkle Tree
    const merkleTree = new MerkleTree(8);

    merkleTree.setLeaf(0n, Poseidon.hash([userPublicKey.x, userBalance]));
    merkleTree.setLeaf(1n, Field.random());
    merkleTree.setLeaf(2n, Field.random());
    merkleTree.setLeaf(3n, Field.random());

    const voterRoot = merkleTree.getRoot();

    const merkleWitness = merkleTree.getWitness(0n);
    const merkleProof = new MyMerkleWitness(merkleWitness);

    const userState = UserState.create(
      nullifier,
      encryptionPublicKey,
      voterRoot,
      userPublicKey,
      electionID
    );

    const { verificationKey } = await UserCircuit.compile();
    fs.writeFileSync(
      path.join(__dirname, '/keys/user_circuit_verification_key.json'),
      JSON.stringify(verificationKey)
    );

    const userProof = await UserCircuit.generateProof(
      userState,
      userSignature,
      vote,
      voteWeight,
      salt,
      userBalance,
      merkleProof
    );

    const result = await verify(userProof, verificationKey);
    expect(result).toBe(true);
  });
});
