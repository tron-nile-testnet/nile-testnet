package org.tron.common.crypto.pqc;

import java.security.SignatureException;
import java.util.Locale;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.crypto.Hash;

/**
 * Micro-benchmark comparing key generation, signing and verification latency for
 * secp256k1 ECDSA (ECKey), FN-DSA-512 (Falcon-512) and ML-DSA-44 (Dilithium-2).
 * Numbers are reported in microseconds (avg of {@link #ITERATIONS} iterations after
 * {@link #WARMUP} warm-up rounds).
 */
public class SignatureSchemeBenchmarkTest {

  private static final int WARMUP = 20;
  private static final int ITERATIONS = 500;
  private static final byte[] MESSAGE = "tron-pq-benchmark-message".getBytes();
  private static final byte[] MESSAGE_HASH = Hash.sha3(MESSAGE);

  @Test
  public void benchmarkAllSchemes() {
    Result eckey = benchEcKey();
    Result fndsa = benchFnDsa();
    Result mldsa = benchMlDsa();

    System.out.println(String.format(Locale.ROOT,
        "=== Signature scheme benchmark (avg over %d iterations, warmup %d) ===",
        ITERATIONS, WARMUP));
    System.out.println(String.format(Locale.ROOT,
        "%-12s | %12s | %12s | %12s",
        "scheme", "keygen (us)", "sign (us)", "verify (us)"));
    System.out.println("-------------+--------------+--------------+--------------");
    printResult(eckey);
    printResult(fndsa);
    printResult(mldsa);
  }

  private Result benchEcKey() {
    for (int i = 0; i < WARMUP; i++) {
      ECKey k = new ECKey();
      ECDSASignature s = k.sign(MESSAGE_HASH);
      try {
        ECKey.signatureToAddress(MESSAGE_HASH, s);
      } catch (SignatureException e) {
        throw new AssertionError(e);
      }
    }

    long keygenNs = 0;
    ECKey[] keys = new ECKey[ITERATIONS];
    for (int i = 0; i < ITERATIONS; i++) {
      long t0 = System.nanoTime();
      keys[i] = new ECKey();
      keygenNs += System.nanoTime() - t0;
    }

    long signNs = 0;
    ECDSASignature[] sigs = new ECDSASignature[ITERATIONS];
    for (int i = 0; i < ITERATIONS; i++) {
      long t0 = System.nanoTime();
      sigs[i] = keys[i].sign(MESSAGE_HASH);
      signNs += System.nanoTime() - t0;
    }

    long verifyNs = 0;
    for (int i = 0; i < ITERATIONS; i++) {
      long t0 = System.nanoTime();
      try {
        ECKey.signatureToAddress(MESSAGE_HASH, sigs[i]);
      } catch (SignatureException e) {
        throw new AssertionError(e);
      }
      verifyNs += System.nanoTime() - t0;
    }
    return new Result("ECKey(secp)", keygenNs, signNs, verifyNs);
  }

  private Result benchFnDsa() {
    for (int i = 0; i < WARMUP; i++) {
      FNDSA512 k = new FNDSA512();
      byte[] sig = k.sign(MESSAGE);
      k.verify(MESSAGE, sig);
    }

    long keygenNs = 0;
    FNDSA512[] keys = new FNDSA512[ITERATIONS];
    for (int i = 0; i < ITERATIONS; i++) {
      long t0 = System.nanoTime();
      keys[i] = new FNDSA512();
      keygenNs += System.nanoTime() - t0;
    }

    long signNs = 0;
    byte[][] sigs = new byte[ITERATIONS][];
    for (int i = 0; i < ITERATIONS; i++) {
      long t0 = System.nanoTime();
      sigs[i] = keys[i].sign(MESSAGE);
      signNs += System.nanoTime() - t0;
    }

    long verifyNs = 0;
    for (int i = 0; i < ITERATIONS; i++) {
      long t0 = System.nanoTime();
      keys[i].verify(MESSAGE, sigs[i]);
      verifyNs += System.nanoTime() - t0;
    }
    return new Result("FN-DSA-512", keygenNs, signNs, verifyNs);
  }

  private Result benchMlDsa() {
    for (int i = 0; i < WARMUP; i++) {
      MLDSA44 k = new MLDSA44();
      byte[] sig = k.sign(MESSAGE);
      k.verify(MESSAGE, sig);
    }

    long keygenNs = 0;
    MLDSA44[] keys = new MLDSA44[ITERATIONS];
    for (int i = 0; i < ITERATIONS; i++) {
      long t0 = System.nanoTime();
      keys[i] = new MLDSA44();
      keygenNs += System.nanoTime() - t0;
    }

    long signNs = 0;
    byte[][] sigs = new byte[ITERATIONS][];
    for (int i = 0; i < ITERATIONS; i++) {
      long t0 = System.nanoTime();
      sigs[i] = keys[i].sign(MESSAGE);
      signNs += System.nanoTime() - t0;
    }

    long verifyNs = 0;
    for (int i = 0; i < ITERATIONS; i++) {
      long t0 = System.nanoTime();
      keys[i].verify(MESSAGE, sigs[i]);
      verifyNs += System.nanoTime() - t0;
    }
    return new Result("ML-DSA-44", keygenNs, signNs, verifyNs);
  }

  private static void printResult(Result r) {
    System.out.println(String.format(Locale.ROOT,
        "%-12s | %12.2f | %12.2f | %12.2f",
        r.name,
        r.keygenNs / 1_000.0 / ITERATIONS,
        r.signNs / 1_000.0 / ITERATIONS,
        r.verifyNs / 1_000.0 / ITERATIONS));
  }

  private static final class Result {
    final String name;
    final long keygenNs;
    final long signNs;
    final long verifyNs;

    Result(String name, long keygenNs, long signNs, long verifyNs) {
      this.name = name;
      this.keygenNs = keygenNs;
      this.signNs = signNs;
      this.verifyNs = verifyNs;
    }
  }
}
