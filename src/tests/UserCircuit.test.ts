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
import * as paillierBigint from 'paillier-bigint';
import { generateEncryptionKeyPair } from '../utils/Pallier';
import { EncryptionPublicKey } from '../utils/PallierZK';

const __dirname = path.resolve();

describe('User Circuit Test', () => {
  let encryptionPrivateKey: paillierBigint.PrivateKey;
  let encryptionPublicKey: paillierBigint.PublicKey;

  let userPrivateKey: PrivateKey;
  let userPublicKey: PublicKey;

  let electionID = Field(1);

  beforeAll(async () => {
    // Generate Paillier Keys
    const { publicKey, privateKey } = await generateEncryptionKeyPair();
    encryptionPrivateKey = privateKey;
    encryptionPublicKey = publicKey;
    console.log('Encryption Private Key: ', encryptionPrivateKey);
    console.log('Encryption Public Key: ', encryptionPublicKey);

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

    const encryptedVote = encryptionPublicKey.encrypt(
      vote.toBigInt() * voteWeight.toBigInt()
    );
    console.log('Encrypted Vote: ', encryptedVote);

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
      EncryptionPublicKey.create(
        Field(encryptionPublicKey.n),
        Field(encryptionPublicKey.g)
      ),
      voterRoot,
      userPublicKey,
      electionID,
      Field(encryptedVote)
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
