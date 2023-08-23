import { Field, Bool, Provable } from 'snarkyjs';

export const exp = (base: Field, exponent: Field) => {
  let bits = exponent.toBits();
  let n = base;

  // this keeps track of when we can start accumulating
  let start = Bool(false);

  // we have to go in reverse order here because .toBits is in LSB representation, but we need MSB for the algorithm to function
  for (let i = 254; i >= 0; i--) {
    let bit = bits[i];

    // we utilize the square and multiply algorithm
    // if the current bit = 0, square and multiply
    // if bit = 1, just square
    let isOne = start.and(bit.equals(false));
    let isZero = start.and(bit.equals(true));

    let square = n.square();
    // we choose what computation to apply next
    n = Provable.switch([isOne, isZero, start.not()], Field, [
      square,
      square.mul(base),
      n,
    ]);

    // toggle start to accumulate; we only start accumulating once we have reached the first 1
    start = Provable.if(bit.equals(true).and(start.not()), Bool(true), start);
  }

  return n;
};
