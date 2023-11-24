import { Cache, Field, Nullifier, PublicKey, Signature } from 'o1js';
import { EncryptionPublicKey } from '../circuits/utils/paillier';
import { WhitelistMerkleWitness } from '../circuits/voting_strategies/whitelist';
import { VoterCircuit, VoterState } from '../circuits/voter_circuit';

interface VoterProofWitness {
  voterWhitelistRootStr: string;
  proposalIdStr: string;
  encryptedVoteStr: string[];
  encryptionPubKeyStr: string;
  voterNullifierKeyStr: string;
  voteStr: string[];
  r_encStr: string;
  voterPubKeyStr: string;
  voterProofStr: string;
  voterSigStr: string;
  voterNullifierStr: string;
}

const generateVoterProof = async (
  witness: VoterProofWitness,
  cacheLocation: string
): Promise<string> => {
  const voterWhitelistRoot = Field(witness.voterWhitelistRootStr);
  const proposalId = Field(witness.proposalIdStr);
  const encryptedVote = witness.encryptedVoteStr.map((str) => Field(str));

  const encryptionPubKeyJson = JSON.parse(witness.encryptionPubKeyStr);
  const encryptionPubKey = new EncryptionPublicKey({
    n: Field(encryptionPubKeyJson.n),
    g: Field(encryptionPubKeyJson.g),
    n_2: Field(encryptionPubKeyJson.n_2),
  });

  const voterNullifierKey = Field(witness.voterNullifierKeyStr);
  const vote = witness.voteStr.map((str) => Field(str));
  const r_enc = Field(witness.r_encStr);

  const voterPubKeyJson = JSON.parse(witness.voterPubKeyStr);
  const voterPubKey = PublicKey.fromJSON(voterPubKeyJson);

  const voterProofJson = JSON.parse(witness.voterProofStr);
  const voterProof = WhitelistMerkleWitness.fromJSON(voterProofJson);

  const voterSigJson = JSON.parse(witness.voterSigStr);
  const voterSig = Signature.fromJSON(voterSigJson);

  const voterNullifierJson = JSON.parse(witness.voterNullifierStr);
  const voterNullifier = Nullifier.fromJSON(voterNullifierJson);

  const voterState = new VoterState({
    voterWhitelistRoot,
    proposalId,
    encryptedVote,
    encryptionPubKey,
    voterNullifierKey,
  });

  const cache = Cache.FileSystem(cacheLocation);
  await VoterCircuit.compile({ cache });

  console.time('Generating voter proof...');
  const proof = await VoterCircuit.generateProof(
    voterState,
    vote,
    r_enc,
    voterPubKey,
    voterProof,
    voterSig,
    voterNullifier
  );
  console.timeEnd('Generating voter proof...');

  proof.verify();

  return JSON.stringify(proof.toJSON());
};

export { generateVoterProof, VoterProofWitness };
