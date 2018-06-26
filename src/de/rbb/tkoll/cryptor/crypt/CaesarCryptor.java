package de.rbb.tkoll.cryptor.crypt;

import java.util.Base64;
import de.rbb.tkoll.cryptor.crypt.AlgoInfo.AlgoProperty;

public class CaesarCryptor extends AbstractCryptor {

  public CaesarCryptor(AlgoInfo info) {
    this.setAlgorithmName(info.getName());
    for (AlgoProperty i : info.getProperties()) {
      this.setProperty(i.getKey(), i.getValue());
    }
    this.setProperty("prop.algo.caesar.shift", 1);
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
        input = java.util.Base64.getDecoder().decode(input);
        break;

      case "raw":
      default:
        break;
    }
    int iShift;
    try {
      iShift = Integer.parseInt(getProperty("prop.algo.caesar.shift"));
    } catch (Exception e) {
      Cryptor.logger.error("Unparsable shift {}", getProperty("prop.algo.caesar.shift"));
      iShift = 0;
    }
    mode = (mode == null) ? Mode.ENCRYPT : mode;
    final char[] arr;
    switch (mode) {
      case DECRYPT:
        arr = new String(input).toCharArray();

        for (int i = 0; i < arr.length; i++) {
          arr[i] = (char) (arr[i] + iShift);
        }
        output = new String(arr).getBytes();
        break;
      case ENCRYPT:
      default:
        arr = new String(input).toCharArray();

        for (int i = 0; i < arr.length; i++) {
          arr[i] = (char) (arr[i] - iShift);
        }
        output = new String(arr).getBytes();
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
