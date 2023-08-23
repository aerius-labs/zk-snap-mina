import {
  Poseidon,
  Experimental,
  Signature,
  Field,
  MerkleWitness,
  Struct,
  Nullifier,
  PublicKey,
} from 'snarkyjs';
import { EncryptionPublicKey } from '../utils/PallierZK';

export class UserState extends Struct({
  // Public
  nullifier: Nullifier,
  encryptionPublicKey: EncryptionPublicKey,
  voterRoot: Field,
  userPublicKey: PublicKey,
  electionID: Field,
  encrypted_vote: Field,
}) {
  static create(
    nullifier: Nullifier,
    encryptionPublicKey: EncryptionPublicKey,
    voterRoot: Field,
    userPublicKey: PublicKey,
    electionID: Field,
    encrypted_vote: Field
  ) {
    return new UserState({
      nullifier,
      encryptionPublicKey,
      voterRoot,
      userPublicKey,
      electionID,
      encrypted_vote,
    });
  }
}

export class MyMerkleWitness extends MerkleWitness(8) {}

export const UserCircuit = Experimental.ZkProgram({
  publicInput: UserState,

  methods: {
    generateProof: {
      privateInputs: [Signature, Field, Field, Field, Field, MyMerkleWitness],

      method(
        userState: UserState,
        userSignature: Signature,
        vote: Field,
        voteWeight: Field,
        salt: Field,
        userBalance: Field,
        merkleProof: MyMerkleWitness
      ) {
        // Check if voteWeight <= userBalance
        voteWeight.assertLessThanOrEqual(userBalance);

        // Construct merkle leaf
        const merkleLeaf = Poseidon.hash([
          userState.userPublicKey.x,
          userBalance,
        ]);

        // Verify against merkleRoot using merkleProof
        merkleProof.calculateRoot(merkleLeaf).assertEquals(userState.voterRoot);

        // TODO
        // Encrypt vote and verify against input

        // Check if userSignature is generated by userPrivateKey
        userSignature.verify(userState.userPublicKey, [
          userState.userPublicKey.x,
          userState.electionID,
        ]);

        // Verify the nullifier
        userState.nullifier.verify([
          userState.userPublicKey.x,
          userState.electionID,
        ]);
      },
    },
  },
});