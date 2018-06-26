package de.rbb.tkoll.cryptor;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.imageio.ImageIO;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.sun.glass.ui.ClipboardAssistance;
import javafx.application.Platform;
import javafx.beans.property.Property;
import javafx.beans.property.SimpleObjectProperty;
import javafx.embed.swing.SwingFXUtils;
import javafx.scene.image.Image;
import javafx.scene.input.Clipboard;
import javafx.scene.input.DataFormat;

/**
 * 
 * @author Tobias Koll
 *
 */
public class ClipboardHook {

  private static ClipboardHook instance;

  private static ClipboardHook getInstance() {
    if (instance == null)
      instance = new ClipboardHook();
    return instance;
  }

  private final Logger              logger = LogManager.getLogger(getClass());
  private final Property<Object>    observable;
  private final ClipboardAssistance assi;
  private final Clipboard           clipboard;

  public ClipboardHook() {
    observable = new SimpleObjectProperty<Object>(null);
    clipboard = Clipboard.getSystemClipboard();
    assi = new com.sun.glass.ui.ClipboardAssistance(com.sun.glass.ui.Clipboard.SYSTEM) {
      @Override
      public void contentChanged() {
        if (clipboard.hasString()) {
          final String s = clipboard.getString();
          if (s != null) {
            observable.setValue(s.getBytes());
          }
        } else if (clipboard.hasImage()) {
          final Image img = clipboard.getImage();
          final BufferedImage bimg = SwingFXUtils.fromFXImage(img, null);
          try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            ImageIO.write(bimg, "png", os);
            observable.setValue(os.toByteArray());
          } catch (IOException e) {
            logger.error(e);
          }
        } else if (clipboard.hasFiles()) {
          logger.info("Auto-gathering of files to be implemented. Files: {}", clipboard.getFiles());
        }
      }
    };
    Runtime.getRuntime().addShutdownHook(new Thread(() -> Platform.runLater(() -> assi.close())));
  }

  /**
   * 
   * @return
   */
  public static Property<Object> valueProperty() {
    return getInstance().observable;
  }

  /**
   * 
   * @param data
   */
  public static void setData(String data) {
    getInstance().assi.setData(DataFormat.PLAIN_TEXT.toString(), data);
    getInstance().assi.flush();
  }

}
