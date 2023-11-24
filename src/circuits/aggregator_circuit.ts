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
        _: AggregatorState,
        earlierProof: SelfProof<AggregatorState, void>,
        voterProof: SelfProof<VoterState, void>,
        nullifierWitness: MerkleMapWitness
      ) {
        earlierProof.verify();
        voterProof.verify();

        earlierProof.publicInput.voterWhitelistRoot.assertEquals(
          voterProof.publicInput.voterWhitelistRoot
        );

        earlierProof.publicInput.proposalId.assertEquals(
          voterProof.publicInput.proposalId
        );

        earlierProof.publicInput.encryptionPubKey.assertEquals(
          voterProof.publicInput.encryptionPubKey
        );
      },
    },
  },
});

export { AggregatorState, AggregatorCircuit };
