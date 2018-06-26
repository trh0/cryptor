package de.rbb.tkoll.cryptor.crypt;

import java.lang.reflect.Constructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import de.rbb.tkoll.cryptor.crypt.AlgoInfo.AlgoProperty;

public interface Cryptor {

  public enum Mode {
    ENCRYPT, DECRYPT, HASH;
  }

  static Logger logger = LogManager.getLogger(Cryptor.class);

  String setProperty(String key, Object value);

  Object getProperty(String key);

  byte[] execute(byte[] input) throws Exception;

  byte[] execute(byte[] input, Mode mode) throws Exception;

  String getAlgorithmName();

  public static Cryptor fromAlgoInfo(AlgoInfo info) {
    Cryptor cryptor = null;
    try {
      AlgoProperty property = info.getProperty("prop.algo.impl.class");
      String className = property.getValue();
      if (property != null && className != null) {
        Constructor<?>[] constructors = Class.forName(className).getConstructors();
        for (Constructor<?> c : constructors) {
          cryptor = (Cryptor) c.newInstance(info);
          break;
        }
      }
    } catch (Exception e) {
      logger.error(e);
    }
    logger.debug("cryptor" + ((cryptor == null) ? " not" : "") + " initialized for info {}", info);
    return cryptor;
  }

  /**
   * 
   * @param key
   * @return
   */
  public static byte[] enrichKey(byte[] key, int glen) {
    byte[] res;
    int i, len = key.length;
    res = new byte[glen];
    for (i = 0; i < glen; i++) {
      if (i < len) {
        res[i] = key[i];
      } else {
        res[i] = (byte) (i ^ 0xF0);
      }
    }
    return res;
  }
}
