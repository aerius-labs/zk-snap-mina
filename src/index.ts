import { generateVoterProof, VoterProofWitness } from './scripts/voter_circuit';
import {
  generateAggregatorBaseProof,
  generateAggregatorRecursiveProof,
  AggregatorBaseProofWitness,
  AggregatorRecursiveProofWitness,
} from './scripts/aggregator_circuit';

export {
  VoterProofWitness,
  AggregatorBaseProofWitness,
  AggregatorRecursiveProofWitness,
  generateVoterProof,
  generateAggregatorBaseProof,
  generateAggregatorRecursiveProof,
};
