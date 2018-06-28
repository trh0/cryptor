package de.rbb.tkoll.cryptor.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Base64;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.Key;
import de.rbb.tkoll.cryptor.crypt.AlgoInfo.AlgoProperty;

public class PGPCryptor extends AbstractCryptor {

  public PGPCryptor(AlgoInfo info) {
    this.setAlgorithmName(info.getName());
    for (AlgoProperty i : info.getProperties()) {
      this.setProperty(i.getKey(), i.getValue());
    }
  }

  @Override
  public byte[] execute(byte[] input) throws Exception {
    return this.execute(input, Mode.ENCRYPT);
  }

  @Override
  public byte[] execute(byte[] input, Mode mode) throws Exception {
    byte[] output = input;
    if (input == null || input.length < 1) {
      Cryptor.logger.debug("Encryption: Empty input");
      return output;
    }
    String privateKeyPw = getProperty("prop.algo.pgp.password");
    if (privateKeyPw == null || privateKeyPw.trim().isEmpty()) {
      Cryptor.logger.warn("PGP Encryption: Password for secret key is empty {}", privateKeyPw);
      return output;
    }

    String privateKey = getProperty("prop.algo.pgp.privatekey");
    if (privateKey == null || privateKey.trim().isEmpty()) {
      Cryptor.logger.warn("PGP Encryption: Path to Secret key is empty {}", privateKey);
      return output;
    }
    Key pKey = null;
    try {
      logger.info("{} -- {}", privateKey, privateKeyPw);
      privateKey = new String(Files.readAllBytes(new File(privateKey).toPath()));
      logger.info("{}", privateKey);
      pKey = new Key(privateKey, privateKeyPw);
    } catch (Exception e) {
      Cryptor.logger.error("Unable to read private key", e);
      return output;
    }

    String inputType = getProperty("prop.algo.input");
    if (inputType == null) {
      Cryptor.logger.warn("Inputtype: Nothing specified {}", inputType);
      inputType = "raw";
    }
    switch (inputType) {
      case "raw":
        break;

      case "hex":
        input = org.bouncycastle.util.encoders.Hex.decode(input);
        break;

      case "Base64":
        input = Base64.getDecoder().decode(input);
        break;

      default:
        break;
    }
    mode = (mode == null) ? Mode.HASH : mode;

    switch (mode) {
      case HASH:
      case ENCRYPT:
        Encryptor e = new Encryptor(pKey);
        try (InputStream is = new ByteArrayInputStream(input);
            ByteArrayOutputStream os = new ByteArrayOutputStream();) {
          e.encrypt(is, os);
          output = os.toByteArray();
        } catch (Exception ex) {
          logger.error("Unable to decrypt cipher text", ex);
        }
        break;
      case DECRYPT:
        Decryptor d = new Decryptor(pKey);
        try (InputStream is = new ByteArrayInputStream(input);
            ByteArrayOutputStream os = new ByteArrayOutputStream();) {
          d.decrypt(is, os);
          output = os.toByteArray();
        } catch (Exception ex) {
          logger.error("Unable to decrypt cipher text", ex);
        }
      default:
        break;
    }
    String outputType = getProperty("prop.algo.output");
    if (outputType == null) {
      Cryptor.logger.warn("Outputtype: Nothing specified {}", privateKeyPw);
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
