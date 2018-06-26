package de.rbb.tkoll.cryptor.crypt;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class AbstractCryptor implements Cryptor {

  static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
  static {
    Security.addProvider(PROVIDER);
  }
  private final Map<String, Object> properties;
  private String                    algorithm;

  void setAlgorithmName(String algorithm) {
    this.algorithm = algorithm;
  }

  public AbstractCryptor() {
    this.properties = new HashMap<>();
  }

  AbstractCryptor(String algorithmName) {
    this.properties = new HashMap<>();
  }

  @Override
  public String setProperty(String key, Object value) {
    return String.valueOf(this.properties.put(key, value));
  }

  @Override
  public String getAlgorithmName() {
    return this.algorithm;
  }

  @Override
  public String getProperty(String key) {
    return String.valueOf(this.properties.get(key));
  }

}
