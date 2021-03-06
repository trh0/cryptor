package de.rbb.tkoll.cryptor;

import java.util.ResourceBundle;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
/**
 * 
 * @author Tobias Koll 
 *
 */
public class CryptorApplication extends Application {

  private static final Logger logger = LogManager.getLogger(CryptorApplication.class);
  
  public static void main(String[] args) throws Exception {
    Application.launch(args);
  }

  @Override
  public void start(Stage stage) throws Exception {
    ClipboardHook.valueProperty();
    ResourceBundle bundle = ResourceBundle.getBundle("messages");
    
    UIController view = new UIController();
    view.bundle(bundle);
    try {
      final FXMLLoader loader = new FXMLLoader();

	  loader.setResources(bundle);
      loader.setLocation(getClass().getClassLoader().getResource("Cryptor.fxml"));
      loader.setController(view);
      loader.setRoot(view);

      loader.load();

    } catch (Exception e) {
      logger.error(e, e.getCause());
      e.printStackTrace();
      System.exit(1);
    }

    Scene scene = new Scene(view);
    stage.setScene(scene);
    stage.sizeToScene();
    stage.setOnCloseRequest((e) -> Platform.exit());
    stage.setTitle(bundle.getString("window.title"));
    stage.show();

  }

}
