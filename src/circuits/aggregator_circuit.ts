import {
  Field,
  MerkleMapWitness,
  Provable,
  SelfProof,
  Struct,
  ZkProgram,
} from 'o1js';
import { EncryptionPublicKey } from './utils/paillier';
import { VoterCircuit, VoterState } from './voter_circuit';
import {
  assertNullifierUnused,
  setNullifierUsed,
} from './vote_validation/vote_validation';

class AggregatorState extends Struct({
  encryptionPubKey: EncryptionPublicKey,
  proposalId: Field,
  voterWhitelistRoot: Field,
  oldNullifierRoot: Field,
  newNullifierRoot: Field,
  oldVoteCount: Provable.Array(Field, 5),
  newVoteCount: Provable.Array(Field, 5),
}) {}

const AggregatorCircuit = ZkProgram({
  name: 'AggregatorCircuit',

  publicInput: AggregatorState,

  methods: {
    generateBaseProof: {
      privateInputs: [],

      method(initState: AggregatorState) {
        initState.encryptionPubKey.g.isConstant();
        initState.encryptionPubKey.n.isConstant();
        initState.encryptionPubKey.n_2.isConstant();

        initState.encryptionPubKey.n
          .square()
          .assertEquals(initState.encryptionPubKey.n_2);

        initState.proposalId.isConstant();
        initState.voterWhitelistRoot.isConstant();
        initState.oldNullifierRoot.isConstant();
        initState.newNullifierRoot.isConstant();

        for (let i = 0; i < initState.oldVoteCount.length; i++) {
          initState.oldVoteCount[i].isConstant();
          initState.newVoteCount[i].isConstant();
        }
      },
    },

    generateRecursiveProof: {
      privateInputs: [
        SelfProof,
        ZkProgram.Proof(VoterCircuit),
        MerkleMapWitness,
      ],

      method(
        aggregatorState: AggregatorState,
        earlierProof: SelfProof<AggregatorState, void>,
        voterProof: SelfProof<VoterState, void>,
        nullifierWitness: MerkleMapWitness
      ) {
        earlierProof.verify();
        voterProof.verify();

        earlierProof.publicInput.voterWhitelistRoot.assertEquals(
          voterProof.publicInput.voterWhitelistRoot
        );
        earlierProof.publicInput.voterWhitelistRoot.assertEquals(
          aggregatorState.voterWhitelistRoot
        );

        earlierProof.publicInput.proposalId.assertEquals(
          voterProof.publicInput.proposalId
        );
        earlierProof.publicInput.proposalId.assertEquals(
          aggregatorState.proposalId
        );

        earlierProof.publicInput.encryptionPubKey.assertEquals(
          voterProof.publicInput.encryptionPubKey
        );
        earlierProof.publicInput.encryptionPubKey.assertEquals(
          aggregatorState.encryptionPubKey
        );

        earlierProof.publicInput.newNullifierRoot.assertEquals(
          aggregatorState.oldNullifierRoot
        );

        for (let i = 0; i < 5; i++) {
          earlierProof.publicInput.newVoteCount[i].assertEquals(
            aggregatorState.oldVoteCount[i]
          );
        }

        for (let i = 0; i < 5; i++) {
          earlierProof.publicInput.encryptionPubKey
            .add(
              earlierProof.publicInput.newVoteCount[i],
              voterProof.publicInput.encryptedVote[i]
            )
            .assertEquals(aggregatorState.newVoteCount[i]);
        }

        earlierProof.publicInput.newNullifierRoot.assertEquals(
          aggregatorState.oldNullifierRoot
        );

        assertNullifierUnused(
          voterProof.publicInput.voterNullifierKey,
          nullifierWitness,
          aggregatorState.oldNullifierRoot
        );

        setNullifierUsed(
          voterProof.publicInput.voterNullifierKey,
          nullifierWitness
        ).assertEquals(aggregatorState.newNullifierRoot);
      },
    },
  },
});

export { AggregatorState, AggregatorCircuit };
