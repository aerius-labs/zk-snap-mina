import {
  Field,
  Nullifier,
  Provable,
  PublicKey,
  Signature,
  Struct,
  ZkProgram,
} from 'o1js';
import {
  WhitelistMerkleWitness,
  verifyLeafInWhitelist,
} from './voting_strategies/whitelist';
import { EncryptionPublicKey } from './utils/paillier';
import { verifyEncryption } from './vote_validation/encryption';
import {
  verifyNullifier,
  verifyPubKeyOwnership,
} from './vote_validation/vote_validation';

class VoterState extends Struct({
  voterWhitelistRoot: Field,
  proposalId: Field,
  encryptedVote: Provable.Array(Field, 5),
  encryptionPubKey: EncryptionPublicKey,
  voterNullifierKey: Field,
}) {}

const VoterCircuit = ZkProgram({
  name: 'VoterCircuit',

  publicInput: VoterState,

  methods: {
    generateProof: {
      privateInputs: [
        Provable.Array(Field, 5),
        Field,
        PublicKey,
        WhitelistMerkleWitness,
        Signature,
        Nullifier,
      ],

      method(
        voterState: VoterState,
        vote: Field[],
        r_enc: Field,
        voterPubKey: PublicKey,
        voterProof: WhitelistMerkleWitness,
        voterSig: Signature,
        voterNullifier: Nullifier
      ) {
        verifyPubKeyOwnership(voterSig, voterPubKey, voterState.proposalId);

        Field(voterState.encryptedVote.length).assertEquals(vote.length);
        for (let i = 0; i < vote.length; i++) {
          verifyEncryption(
            voterState.encryptionPubKey,
            voterState.encryptedVote[i],
            vote[i],
            r_enc
          );
        }

        verifyLeafInWhitelist(
          voterState.voterWhitelistRoot,
          [voterPubKey.x],
          voterProof
        );

        verifyNullifier(voterNullifier, voterState.voterNullifierKey, [
          voterState.proposalId,
          voterPubKey.x,
        ]);
      },
    },
  },
});

export { VoterState, VoterCircuit };
