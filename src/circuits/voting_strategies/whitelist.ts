import { Field, MerkleWitness, Poseidon } from 'o1js';

// TODO - figure out a way to instantiate this while compiling circuit.
class WhitelistMerkleWitness extends MerkleWitness(8) {}

const verifyLeafInWhitelist = (
  root: Field,
  leafPreimage: Field[],
  proof: WhitelistMerkleWitness
) => {
  const leaf = Poseidon.hash(leafPreimage);
  proof.calculateRoot(leaf).assertEquals(root);
};

export { verifyLeafInWhitelist, WhitelistMerkleWitness };
