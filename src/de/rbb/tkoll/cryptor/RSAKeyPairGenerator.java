package de.rbb.tkoll.cryptor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * A simple utility class that generates a RSA PGPPublicKey/PGPSecretKey pair.
 * <p>
 * usage: RSAKeyPairGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are placed in the files
 * pub.[asc|bpg] and secret.[asc|bpg].
 */
public class RSAKeyPairGenerator {

  public void exportKeyPair(OutputStream secretOut, OutputStream publicOut, PublicKey publicKey,
      PrivateKey privateKey, String identity, char[] passPhrase, boolean armor)
      throws PGPException, IOException {
    if (armor) {
      secretOut = new ArmoredOutputStream(secretOut);
    }

    PGPPublicKey a =
        (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey, new Date()));
    RSAPrivateCrtKey rsK = (RSAPrivateCrtKey) privateKey;
    RSASecretBCPGKey privPk =
        new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
    PGPPrivateKey b = new PGPPrivateKey(a.getKeyID(), a.getPublicKeyPacket(), privPk);

    PGPDigestCalculator sha1Calc =
        new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
    PGPKeyPair keyPair = new PGPKeyPair(a, b);
    PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity,
        sha1Calc, null, null,
        new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(),
            HashAlgorithmTags.SHA1),
        new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC")
            .build(passPhrase));

    secretKey.encode(secretOut);

    secretOut.close();

    if (armor) {
      publicOut = new ArmoredOutputStream(publicOut);
    }

    PGPPublicKey key = secretKey.getPublicKey();

    key.encode(publicOut);

    publicOut.close();
  }

  public static final int KEYSIZE_1024BIT = 1024;
  public static final int KEYSIZE_2048BIT = 2048;
  public static final int KEYSIZE_4096BIT = 4096;

  public void genKeyPair(byte[] publicKey, byte[] privateKey, char[] password, int keySize,
      String identify, boolean armored) throws Exception {

    Security.addProvider(new BouncyCastleProvider());

    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("RSA", "BC");
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new PGPException("Fatal", e);
    }

    kpg.initialize(keySize);

    KeyPair kp = kpg.generateKeyPair();

    try (ByteArrayOutputStream out1 = new ByteArrayOutputStream();
        ByteArrayOutputStream out2 = new ByteArrayOutputStream();) {

      this.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), identify, password, armored);

      publicKey = out1.toByteArray();
      privateKey = out2.toByteArray();
    } catch (IOException | PGPException e) {
      throw e;
    }

  }

}
