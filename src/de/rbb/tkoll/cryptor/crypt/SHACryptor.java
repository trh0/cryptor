package de.rbb.tkoll.cryptor.crypt;

import java.util.Base64;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import de.rbb.tkoll.cryptor.crypt.AlgoInfo.AlgoProperty;

public class SHACryptor extends AbstractCryptor {

  public SHACryptor(AlgoInfo info) {
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
      Cryptor.logger.debug("SHA: Empty input");
      return output;
    }

    String inputType = getProperty("prop.algo.input");
    if (inputType == null) {
      Cryptor.logger.warn("Inputtype: Nothing specified {}", inputType);
      inputType = "raw";
    }
    switch (inputType) {
      case "hex":
        input = org.bouncycastle.util.encoders.Hex.decode(input);
        break;

      case "Base64":
        input = Base64.getDecoder().decode(input);
        break;

      case "raw":
      default:
        break;
    }
    String variant = getProperty("prop.algo.variant");
    switch (variant) {
      case "SHA1":
        output = SHA256.Digest.getInstance("SHA-1", "BC").digest(input);
        break;
      case "SHA512":
        output = SHA256.Digest.getInstance("SHA-512", "BC").digest(input);
        break;
      case "SHA256":
      default:
        output = SHA256.Digest.getInstance("SHA-256", "BC").digest(input);
        break;
    }
    String outputType = getProperty("prop.algo.output");
    if (outputType == null) {
      Cryptor.logger.warn("Outputtype: Nothing specified {}", outputType);
      outputType = "raw";
    }
    switch (outputType) {
      case "raw":
        break;

      case "hex":

        output = org.bouncycastle.util.encoders.Hex.encode(output);
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
