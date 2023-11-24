import { Cache, Field, MerkleMapWitness, Proof } from 'o1js';
import { EncryptionPublicKey } from '../circuits/utils/paillier';
import {
  AggregatorCircuit,
  AggregatorState,
} from '../circuits/aggregator_circuit';
import { VoterState } from '../circuits/voter_circuit';

class AggregatorProof extends Proof<AggregatorState, void> {}
class VoterProof extends Proof<VoterState, void> {}

interface AggregatorBaseProofWitness {
  encryptionPubKeyStr: string;
  proposalIdStr: string;
  voterWhitelistRootStr: string;
  oldNullifierRootStr: string;
  newNullifierRootStr: string;
  oldVoteCount: string[];
  newVoteCount: string[];
}

interface AggregatorRecursiveProofWitness extends AggregatorBaseProofWitness {
  earlierProofStr: string;
  voterProofStr: string;
  nullifierWitnessStr: string;
}

const generateAggregatorBaseProof = async (
  witness: AggregatorBaseProofWitness,
  cacheLocation: string
) => {
  const encryptionPubKeyJson = JSON.parse(witness.encryptionPubKeyStr);
  const encryptionPubKey = new EncryptionPublicKey({
    n: Field(encryptionPubKeyJson.n),
    g: Field(encryptionPubKeyJson.g),
    n_2: Field(encryptionPubKeyJson.n_2),
  });

  const proposalId = Field(witness.proposalIdStr);
  const voterWhitelistRoot = Field(witness.voterWhitelistRootStr);
  const oldNullifierRoot = Field(witness.oldNullifierRootStr);
  const newNullifierRoot = Field(witness.newNullifierRootStr);

  const oldVoteCount = witness.oldVoteCount.map((str) => Field(str));
  const newVoteCount = witness.newVoteCount.map((str) => Field(str));

  const aggregatorState = new AggregatorState({
    encryptionPubKey,
    proposalId,
    voterWhitelistRoot,
    oldNullifierRoot,
    newNullifierRoot,
    oldVoteCount,
    newVoteCount,
  });

  const cache = Cache.FileSystem(cacheLocation);
  await AggregatorCircuit.compile({ cache });

  console.time('Generating base proof...');
  const proof = await AggregatorCircuit.generateBaseProof(aggregatorState);
  console.timeEnd('Generating base proof...');

  proof.verify();

  return JSON.stringify(proof.toJSON());
};

const generateAggregatorRecursiveProof = async (
  witness: AggregatorRecursiveProofWitness,
  cacheLocation: string
) => {
  const encryptionPubKeyJson = JSON.parse(witness.encryptionPubKeyStr);
  const encryptionPubKey = new EncryptionPublicKey({
    n: Field(encryptionPubKeyJson.n),
    g: Field(encryptionPubKeyJson.g),
    n_2: Field(encryptionPubKeyJson.n_2),
  });

  const proposalId = Field(witness.proposalIdStr);
  const voterWhitelistRoot = Field(witness.voterWhitelistRootStr);
  const oldNullifierRoot = Field(witness.oldNullifierRootStr);
  const newNullifierRoot = Field(witness.newNullifierRootStr);

  const oldVoteCount = witness.oldVoteCount.map((str) => Field(str));
  const newVoteCount = witness.newVoteCount.map((str) => Field(str));

  const aggregatorState = new AggregatorState({
    encryptionPubKey,
    proposalId,
    voterWhitelistRoot,
    oldNullifierRoot,
    newNullifierRoot,
    oldVoteCount,
    newVoteCount,
  });

  const earlierProofJson = JSON.parse(witness.earlierProofStr);
  const earlierProof = AggregatorProof.fromJSON(earlierProofJson);

  const voterProofJson = JSON.parse(witness.voterProofStr);
  const voterProof = VoterProof.fromJSON(voterProofJson);

  const nullifierWitnessJson = JSON.parse(witness.nullifierWitnessStr);
  const nullifierWitness = MerkleMapWitness.fromJSON(nullifierWitnessJson);

  const cache = Cache.FileSystem(cacheLocation);
  await AggregatorCircuit.compile({ cache });

  console.time('Generating recursive proof...');
  const proof = await AggregatorCircuit.generateRecursiveProof(
    aggregatorState,
    earlierProof,
    voterProof,
    nullifierWitness
  );
  console.timeEnd('Generating recursive proof...');

  proof.verify();

  return JSON.stringify(proof.toJSON());
};

export {
  AggregatorBaseProofWitness,
  AggregatorRecursiveProofWitness,
  generateAggregatorBaseProof,
  generateAggregatorRecursiveProof,
};
