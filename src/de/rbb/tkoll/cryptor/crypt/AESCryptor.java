package de.rbb.tkoll.cryptor.crypt;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import de.rbb.tkoll.cryptor.crypt.AlgoInfo.AlgoProperty;

public class AESCryptor extends AbstractCryptor {

  public AESCryptor(AlgoInfo info) {
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
    String sKey = getProperty("prop.algo.aes.key");
    if (sKey == null || sKey.isEmpty()) {
      Cryptor.logger.warn("AES Encryption: Secret empty {}", sKey);
      return output;
    }
    byte[] key = sKey.getBytes();
    Cipher cipher;

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
    mode = (mode == null) ? Mode.HASH : mode;
    int keysize = 16;
    key = Cryptor.enrichKey(key, keysize);

    switch (mode) {
      case HASH:
      case ENCRYPT:
        cipher = Cipher.getInstance("AES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        output = cipher.doFinal(input);
        break;
      case DECRYPT:
        cipher = Cipher.getInstance("AES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        output = cipher.doFinal(input);
      default:
        break;
    }
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
