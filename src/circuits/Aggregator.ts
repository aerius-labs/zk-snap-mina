import {
  Experimental,
  Field,
  PublicKey,
  SelfProof,
  SmartContract,
  State,
  ZkProgram,
  method,
  state,
} from 'o1js';
import { AggregatorCircuit, AggregatorState } from './AggregatorCircuit';
import { EncryptionPublicKey } from '../utils/PallierZK';

let AggregatorProof_ = ZkProgram.Proof(AggregatorCircuit);
class AggregatorProof extends AggregatorProof_ {}

export class Aggregator extends SmartContract {
  @state(Field) electionID = State<Field>();
  @state(EncryptionPublicKey) encryptionPublicKey =
    State<EncryptionPublicKey>();
  @state(Field) voterRoot = State<Field>();
  @state(Field) voteCount = State<Field>();

  @method initializeElection(baseProof: AggregatorProof): void {
    // Verify the Base Aggregator Proof
    baseProof.verify();

    // Verify if the Encryption Public Key matches
    this.encryptionPublicKey.set(baseProof.publicInput.encryptionPublicKey);

    // Verify if the election ID matches
    this.electionID.set(baseProof.publicInput.electionID);

    // Verify if the Voter Root matches
    this.voterRoot.set(baseProof.publicInput.voterRoot);

    // Verify if the old and new Nullifier Root matches
    baseProof.publicInput.oldNullifierRoot.assertEquals(
      baseProof.publicInput.newNullifierRoot
    );

    // Verify if the nonce is 0
    baseProof.publicInput.nonce.assertEquals(Field(0));

    // Verify if the vote count is 0
    baseProof.publicInput.oldVoteCount.assertEquals(
      baseProof.publicInput.newVoteCount
    );
    this.voteCount.set(baseProof.publicInput.newVoteCount);
  }

  @method finalizeElection(finalProof: AggregatorProof): void {
    // Verify the Final Aggregator Proof
    finalProof.verify();

    // Verify if the Encryption Public Key matches
    this.encryptionPublicKey.assertEquals(
      finalProof.publicInput.encryptionPublicKey
    );

    // Verify if the election ID matches
    this.electionID.assertEquals(finalProof.publicInput.electionID);

    // Verify if the Voter Root matches
    this.voterRoot.assertEquals(finalProof.publicInput.voterRoot);

    // Verify if the old and new Nullifier Root do not match
    finalProof.publicInput.oldNullifierRoot.assertNotEquals(
      finalProof.publicInput.newNullifierRoot
    );

    // Verify if the nonce is greater than 0
    finalProof.publicInput.nonce.assertGreaterThan(Field(0));

    // set final vote count
    this.voteCount.set(finalProof.publicInput.newVoteCount);
  }
}
