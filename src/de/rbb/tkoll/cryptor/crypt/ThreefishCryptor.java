package de.rbb.tkoll.cryptor.crypt;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;
import de.rbb.tkoll.cryptor.crypt.AlgoInfo.AlgoProperty;

public class ThreefishCryptor extends AbstractCryptor {

  public ThreefishCryptor(AlgoInfo info) {
    this.setAlgorithmName(info.getName());
    for (AlgoProperty i : info.getProperties()) {
      this.setProperty(i.getKey(), i.getValue());
    }
  }

  @Override
  public byte[] execute(byte[] input) throws Exception {
    return this.execute(input, null);
  }

  @Override
  public byte[] execute(byte[] input, Mode mode) throws Exception {
    byte[] output = input;
    if (input == null || input.length < 1) {
      Cryptor.logger.debug("Encryption: Empty input");
      return output;
    }
    String sKey = getProperty("prop.algo.threefish.key");
    if (sKey == null || sKey.isEmpty()) {
      Cryptor.logger.warn("AES Encryption: Secret empty {}", sKey);
      return output;
    }
    byte[] key = sKey.getBytes();
    PaddedBufferedBlockCipher cipher;

    String inputType = getProperty("prop.algo.input");
    if (inputType == null) {
      Cryptor.logger.warn("Inputtype: Nothing specified {}", sKey);
      inputType = "raw";
    }
    switch (inputType) {
      case "raw":
        break;

      case "hex":
        break;

      case "Base64":
        input = Base64.getDecoder().decode(input);
        break;

      default:
        break;
    }
    mode = (mode == null) ? Mode.ENCRYPT : mode;

    String strVariant = getProperty("prop.algo.variant");
    strVariant = ("" + strVariant).trim();
    int keysize =
        "Threefish-256".equals(strVariant) ? 32 : "Threefish-512".equals(strVariant) ? 64 : 128;
    key = Cryptor.enrichKey(key, keysize);
    // KeyGenerator kg = KeyGenerator.getInstance(strVariant, AbstractCryptor.PROVIDER);
    // kg.init(1024);
    // javax.crypto.SecretKey keye = kg.generateKey();
    logger.debug("{} {} {} {}", strVariant, keysize, key.length, key);

    TweakableBlockCipherParameters prms =
        new TweakableBlockCipherParameters(new KeyParameter(key), new byte[16]);
    cipher = new PaddedBufferedBlockCipher(
        new CBCBlockCipher(new ThreefishEngine(keysize == 128 ? ThreefishEngine.BLOCKSIZE_1024
            : keysize == 64 ? ThreefishEngine.BLOCKSIZE_512 : ThreefishEngine.BLOCKSIZE_256)),
        new PKCS7Padding());

    switch (mode) {
      case DECRYPT:
        cipher.init(false, prms);
        break;
      case HASH:
      case ENCRYPT:
      default:
        cipher.init(true, prms);
        break;
    }
    logger.debug("Doing cipher");
    logger.debug("{}{}", output, output.length);
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CipherOutputStream cos = new CipherOutputStream(baos, cipher);) {
      cos.write(input);
      cos.flush();
      cos.close();
      output = baos.toByteArray();
    } catch (Exception e) {
      logger.error("", e);
    }
    logger.debug("{}{}", output, output.length);
    String outputType = getProperty("prop.algo.output");
    if (outputType == null) {
      Cryptor.logger.warn("Outputtype: Nothing specified {}", sKey);
      outputType = "raw";
    }
    switch (outputType) {
      case "raw":
        break;

      case "hex":
        break;

      case "Base64":
        output = Base64.getEncoder().encodeToString(output).getBytes();
        break;

      default:
        break;
    }
    return output;
  }

}
