import {
  Field,
  PublicKey,
  SelfProof,
  SmartContract,
  State,
  method,
} from 'snarkyjs';
import { AggregatorState } from './AggregatorCircuit';

let electionID: Field;
let encryptionPublicKey: PublicKey;
let voterRoot: Field;

export const setBaseParameters = (
  _electionID: Field,
  _encryptionPublicKey: PublicKey,
  _voterRoot: Field
) => {
  electionID = _electionID;
  encryptionPublicKey = _encryptionPublicKey;
  voterRoot = _voterRoot;
};

export class Aggregator extends SmartContract {
  electionID = State<Field>();
  encryptionPublicKey = State<PublicKey>();
  voterRoot = State<Field>();
  nonce = State<Field>();

  @method finalizeElection(
    aggregatorState: AggregatorState,
    earlierProof: SelfProof<AggregatorState, void>
  ): void {
    // Verify the Final Aggregator Proof
    earlierProof.verify();

    // Verify if the Encryption Public Key matches
    earlierProof.publicInput.encryptionPublicKey.assertEquals(
      aggregatorState.encryptionPublicKey
    );

    // Verify if the election ID matches
    earlierProof.publicInput.electionID.assertEquals(
      aggregatorState.electionID
    );

    // Verify if the Voter Root matches
    earlierProof.publicInput.voterRoot.assertEquals(aggregatorState.voterRoot);
  }
}
