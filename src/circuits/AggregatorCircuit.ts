import {
  Experimental,
  Field,
  Struct,
  PublicKey,
  SelfProof,
  MerkleMapWitness,
  Provable,
} from 'o1js';
import { UserCircuit, UserState } from './UserCircuit';
import { ZkProgram } from 'o1js/dist/node/lib/proof_system';
import { EncryptionPublicKey } from '../utils/PallierZK';

export class AggregatorState extends Struct({
  encryptionPublicKey: EncryptionPublicKey,
  electionID: Field,
  voterRoot: Field,
  oldNullifierRoot: Field,
  newNullifierRoot: Field,
  nonce: Field,
  oldVoteCount: Field,
  newVoteCount: Field,
}) {
  static create(
    encryptionPublicKey: EncryptionPublicKey,
    electionID: Field,
    voterRoot: Field,
    oldNullifierRoot: Field,
    newNullifierRoot: Field,
    nonce: Field,
    oldVoteCount: Field,
    newVoteCount: Field
  ) {
    return new AggregatorState({
      encryptionPublicKey,
      electionID,
      voterRoot,
      oldNullifierRoot,
      newNullifierRoot,
      nonce,
      oldVoteCount,
      newVoteCount,
    });
  }
}

export const AggregatorCircuit = Experimental.ZkProgram({
  publicInput: AggregatorState,

  methods: {
    generateBaseProof: {
      privateInputs: [],

      method(aggregatorstate: AggregatorState) {
        aggregatorstate.encryptionPublicKey.n.isConstant();
        aggregatorstate.encryptionPublicKey.g.isConstant();
        aggregatorstate.electionID.isConstant();
        aggregatorstate.voterRoot.isConstant();
        aggregatorstate.oldNullifierRoot.isConstant();
        aggregatorstate.newNullifierRoot.isConstant();
        aggregatorstate.nonce.isConstant();

        aggregatorstate.oldNullifierRoot.assertEquals(
          aggregatorstate.newNullifierRoot
        );

        aggregatorstate.nonce.assertEquals(Field(0));

        aggregatorstate.oldVoteCount.assertEquals(aggregatorstate.newVoteCount);
      },
    },

    generateProof: {
      privateInputs: [
        SelfProof,
        ZkProgram.Proof(UserCircuit),
        MerkleMapWitness,
      ],

      method(
        aggregatorState: AggregatorState,
        earlierProof: SelfProof<AggregatorState, void>,
        userProof: SelfProof<UserState, void>,
        nullifierWitness: MerkleMapWitness
      ) {
        // Verify the User Proof
        userProof.verify();

        // Verify the Aggregator Proof
        earlierProof.verify();

        // Verify if the Encryption Public Key matches
        userProof.publicInput.encryptionPublicKey.n.assertEquals(
          aggregatorState.encryptionPublicKey.n
        );
        userProof.publicInput.encryptionPublicKey.g.assertEquals(
          aggregatorState.encryptionPublicKey.g
        );

        // Verify if the election ID matches
        userProof.publicInput.electionID.assertEquals(
          aggregatorState.electionID
        );

        // Verify if the Voter Root matches
        userProof.publicInput.voterRoot.assertEquals(aggregatorState.voterRoot);

        // Add the Nullifier to the oldNullifierRoot
        userProof.publicInput.nullifier.assertUnused(
          nullifierWitness,
          aggregatorState.oldNullifierRoot
        );
        let newRoot = userProof.publicInput.nullifier.setUsed(nullifierWitness);
        aggregatorState.newNullifierRoot.assertEquals(newRoot);

        // Verify if the Nonce is correct
        earlierProof.publicInput.nonce.assertEquals(
          aggregatorState.nonce.sub(Field(1))
        );

        const newVoteCount = aggregatorState.encryptionPublicKey.add(
          aggregatorState.oldVoteCount,
          userProof.publicInput.encrypted_vote
        );
        newVoteCount.assertEquals(aggregatorState.newVoteCount);
      },
    },
  },
});
