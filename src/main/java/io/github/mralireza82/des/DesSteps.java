package io.github.mralireza82.des;

import java.util.List;

/**
 * Every intermediate value of one DES encryption, in hexadecimal, so each step can be followed and checked
 * by hand. Produced by {@link SimpleDes#encryptWithSteps(byte[], byte[])}.
 *
 * @param key         the 64-bit key
 * @param keyAfterPc1 the 56 key bits that remain after permuted choice 1 (C0 then D0)
 * @param roundKeys   K1 .. K16, 48 bits each
 * @param block       the 64-bit input block
 * @param afterIp     the block after the initial permutation (L0 then R0)
 * @param rounds      the 16 rounds
 * @param beforeFp    R16 then L16 (the halves swapped once more)
 * @param output      the encrypted block, after the final permutation
 */
public record DesSteps(String key, String keyAfterPc1, List<String> roundKeys, String block, String afterIp,
                       List<Round> rounds, String beforeFp, String output) {

    /**
     * One round: {@code L(n) = R(n-1)} and {@code R(n) = L(n-1) XOR f(R(n-1), Kn)}.
     *
     * @param number      1 .. 16
     * @param expanded    E(R(n-1)), 48 bits
     * @param mixedWithKey E(R(n-1)) XOR Kn, 48 bits
     * @param substituted the eight S-box outputs, 32 bits
     * @param f           P(substituted): the result of the round function, 32 bits
     * @param left        L(n), 32 bits
     * @param right       R(n), 32 bits
     */
    public record Round(int number, String expanded, String mixedWithKey, String substituted, String f,
                        String left, String right) {
    }
}
