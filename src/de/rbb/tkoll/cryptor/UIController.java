package de.rbb.tkoll.cryptor;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.io.Streams;
import org.reactfx.EventStreams;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXCheckBox;
import com.jfoenix.controls.JFXComboBox;
import com.jfoenix.controls.JFXRadioButton;
import com.jfoenix.controls.JFXTextArea;
import de.rbb.tkoll.cryptor.GenericPropertySheet.EditorType;
import de.rbb.tkoll.cryptor.crypt.AlgoInfo;
import de.rbb.tkoll.cryptor.crypt.AlgoInfo.AlgoProperty;
import de.rbb.tkoll.cryptor.crypt.Cryptor;
import de.rbb.tkoll.cryptor.crypt.Cryptor.Mode;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.DialogPane;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToolBar;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class UIController extends GridPane {

  private final Logger logger = LogManager.getLogger(getClass());

  public void bundle(ResourceBundle bundle) {
    this.bundle = bundle;
  }

  public ResourceBundle bundle() {
    return this.bundle;
  }

  @FXML
  private ResourceBundle           bundle;
  @FXML
  private MenuBar                  menuBar;
  @FXML
  private Menu                     menuApp;
  @FXML
  private MenuItem                 menuItemClose, menuItemSettings, menuItemDebug,
      menuItemGenRSAKey;
  @FXML
  private ToolBar                  toolbar;
  @FXML
  private HBox                     hboxToolbar;
  @FXML
  AnchorPane                       anchorPaneProperties;
  @FXML
  private JFXCheckBox              cbClipboard, cbAutoCrypt;
  @FXML
  private JFXRadioButton           rbAutoEncrypt, rbAutoDecrypt;
  @FXML
  JFXComboBox<String>              comboAlgo;
  private GenericPropertySheet     propertySheet;
  @FXML
  private JFXTextArea              textInput, textOutput;
  @FXML
  private JFXButton                btnEncrypt, btnDecrypt, btnLoadContent;

  private Dialog<ButtonType>       dialog;
  private Stage                    modal;

  private ChangeListener<Object>   clipboardListener;

  private ObservableList<AlgoInfo> algorithms;
  private Cryptor                  cryptor;

  @FXML
  void initialize() {
    logger.info("UIController initializing on FXML load.");
    /*
     * Reusable dialog for operations that may intercept the application. Such as opening files or
     * adding pgp keys.
     */
    dialog = new Dialog<>();
    dialog.setOnCloseRequest((value) -> dialog.close());
    final DialogPane dialogPane = dialog.getDialogPane();
    dialogPane.getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);

    menuItemGenRSAKey = new MenuItem(bundle.getString("menu.app.genkey"));
    /**
     * Define actions to generate a RSA key
     */
    menuItemGenRSAKey.setOnAction((e) -> {

      JFXComboBox<Integer> combo = new JFXComboBox<>();
      combo.setPromptText(bundle.getString("prompt.rsa.keysize"));
      combo.getItems().addAll(RSAKeyPairGenerator.KEYSIZE_1024BIT,
          RSAKeyPairGenerator.KEYSIZE_2048BIT, RSAKeyPairGenerator.KEYSIZE_4096BIT);
      combo.setMaxWidth(Double.MAX_VALUE);
      combo.setPrefWidth(250);
      TextField keyfield = new TextField();
      keyfield.setPromptText(bundle.getString("prompt.rsa.password"));

      GenericPropertySheet.addValidator("^[^\\s]{8,}", keyfield);
      keyfield.setMaxWidth(Double.MAX_VALUE);
      keyfield.setPrefWidth(250);

      TextField identity = new TextField();
      identity.setPromptText(bundle.getString("prompt.rsa.identity"));
      GenericPropertySheet.addValidator(".+", identity);
      identity.setMaxWidth(Double.MAX_VALUE);
      identity.setPrefWidth(250);

      VBox box = new VBox();
      box.getChildren().addAll(combo, keyfield, identity);
      VBox.setVgrow(identity, Priority.ALWAYS);
      VBox.setVgrow(combo, Priority.ALWAYS);
      VBox.setVgrow(keyfield, Priority.ALWAYS);
      dialogPane.setContent(box);

      Optional<ButtonType> res = dialog.showAndWait();
      if (res.isPresent()) {

        ButtonType btn = res.get();
        if (ButtonType.OK.equals(btn)) {

          String key = keyfield.getText(), ident = identity.getText();
          Integer keysize = combo.getSelectionModel().getSelectedItem();
          keysize = (keysize == null) ? RSAKeyPairGenerator.KEYSIZE_2048BIT : keysize;
          if (key != null) {

            RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
            byte[] pkey = new byte[0], skey = new byte[0];

            try (ByteArrayOutputStream pubos = new ByteArrayOutputStream();
                ByteArrayOutputStream secos = new ByteArrayOutputStream();) {
              generator.genKeyPair(pubos, secos, key.toCharArray(), keysize, ident, true);
              pkey = pubos.toByteArray();
              skey = secos.toByteArray();

              if (pkey.length > 1 && skey.length > 1) {

                FileChooser chooser = new FileChooser();
                chooser.setTitle(bundle.getString("window.rsa.pubk.save"));
                File file = chooser.showSaveDialog(modal);

                if (file != null) {
                  logger.info("Saving public key to file {}", file);
                  file.delete();
                  Files.write(file.toPath(), pkey, StandardOpenOption.CREATE,
                      StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                      StandardOpenOption.TRUNCATE_EXISTING);
                } else
                  logger.warn("No fileoutput selected for generated RSA public key");

                chooser.setTitle(bundle.getString("window.rsa.prvk.save"));
                file = chooser.showSaveDialog(modal);

                if (file != null) {
                  logger.info("Saving private key to file {}", file);
                  file.delete();
                  Files.write(file.toPath(), skey, StandardOpenOption.CREATE,
                      StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                      StandardOpenOption.TRUNCATE_EXISTING);
                } else
                  logger.warn("No fileoutput selected for generated RSA private key");

              } else {
                logger.error("Could not genreate RSA key");
              }
            } catch (Exception ex) {
              logger.error("", ex);
            }
          }
        }
      }
    });
    menuApp.getItems().add(menuApp.getItems().size() - 2, menuItemGenRSAKey);
    /*
     * Build the ui to show logger optput
     */
    TextArea debugTextArea = new TextArea();
    debugTextArea.textProperty().bind(LogInterceptor.logProperty());
    debugTextArea.setEditable(false);

    modal = new Stage();
    modal.setOnCloseRequest((val) -> modal.close());
    modal.setTitle(bundle.getString("window.title"));

    VBox modalVBox = new VBox();
    JFXButton modalCloseBtn = new JFXButton(bundle.getString("common.close"));
    modalCloseBtn.setOnAction((v) -> modal.close());
    modalCloseBtn.setMaxWidth(Double.MAX_VALUE);
    modalVBox.getChildren().addAll(debugTextArea, modalCloseBtn);
    VBox.setVgrow(modalCloseBtn, Priority.ALWAYS);
    modalVBox.setAlignment(Pos.CENTER);
    Scene modalScene = new Scene(modalVBox);
    modal.setScene(modalScene);
    modal.sizeToScene();

    /*
     * Configure delayed processing of the change of the inputTextArea's textproperty if
     * auto-encrypt is selected.
     */
    EventStreams.valuesOf(textInput.textProperty()).conditionOn(cbAutoCrypt.selectedProperty())
        .successionEnds(Duration.ofMillis(250)).subscribe((value) -> {
          final ActionEvent event = new ActionEvent();
          if (rbAutoEncrypt.isSelected())
            encrypt(event);
          else
            decrypt(event);
        });
    /**
     * Action applied on change of clipboard data
     */
    clipboardListener = (o, ov, nv) -> {
      logger.debug("Clipboard changed.");
      textInput.setText(new String((byte[]) nv));
    };
    /**
     * Activate / deactivate hook via UI.
     */
    cbClipboard.selectedProperty().addListener((o, ov, nv) -> {
      if (nv == true) {
        ClipboardHook.valueProperty().addListener(clipboardListener);
      } else {
        ClipboardHook.valueProperty().removeListener(clipboardListener);
      }
    });

    rbAutoDecrypt.getToggleGroup().selectedToggleProperty()
        .addListener((ChangeListener<Toggle>) (obs, olval, nuval) -> {
          toggle(false);
        });

    try {
      /*
       * Build PropertySheet for algorithm selection
       */
      propertySheet = new GenericPropertySheet();
      propertySheet.setTooltip(new Tooltip(bundle.getString("tooltip.properties")));
      anchorPaneProperties.getChildren().add(propertySheet);
      /**
       * UI Constraints
       */
      AnchorPane.setBottomAnchor(propertySheet, 0d);
      AnchorPane.setLeftAnchor(propertySheet, 0d);
      AnchorPane.setRightAnchor(propertySheet, 0d);
      AnchorPane.setTopAnchor(propertySheet, 0d);
      /**
       * Initialize algorithms available in the application.
       */
      final Gson gson = new Gson();
      try (InputStream is =
          getClass().getClassLoader().getResource("algorithms.json").openStream()) {
        algorithms = FXCollections
            .observableArrayList(gson.fromJson(new String(Streams.readAll(is)), AlgoInfo[].class));
      } catch (JsonSyntaxException | IOException e) {
        logger.error("Unable to deserialize algorithms.json", e, e.getCause());
      } catch (NullPointerException e) {
        logger.error("Unable to deserialize algorithms.json - File not in classpath?", e,
            e.getCause());
      } catch (Exception e) {
        logger.error("Error processing algorithms.json", e, e.getCause());
      }

      if (algorithms == null) {
        logger.error("Unable to initialize algorithms.");
        return;
      }

      List<String> algos = algorithms.stream().map((m) -> m.getName()).collect(Collectors.toList());
      comboAlgo.getItems().addAll(algos);

      comboAlgo.getSelectionModel().selectedItemProperty().addListener((o, ov, nv) -> {
        logger.debug("Algo-selection changed {} to {}", ov, nv);
        propertySheet.getItems().clear();
        Optional<?> optInfo = algorithms.stream().filter((p) -> p.getName().equals(nv)).findFirst();
        if (optInfo.isPresent()) {
          AlgoInfo info = (AlgoInfo) optInfo.get();
          cryptor = Cryptor.fromAlgoInfo(info);
          for (AlgoProperty p : info.getProperties()) {

            String[] defaults = p.getDefaultValues();
            EditorType editorType;
            switch (p.getType()) {
              case "filelist":
                editorType = EditorType.FILELIST;
                break;
              case "file":
                editorType = EditorType.FILE;
                break;
              case "choice":
                editorType = EditorType.CHOICE;
                break;
              case "text":
              default:
                editorType = EditorType.AUTO;
                break;
            }
            GenericPropertySheet.CustomItem it =
                new GenericPropertySheet.CustomItem(p.getKey(), p.getName(), p.getDescription(),
                    p.getValidation(), ((defaults != null) ? defaults[0] : ""), editorType);
            it.setChoices(p.getDefaultValues());
            it.getObservableValue().get()
                .addListener((ChangeListener<Object>) (obs, oobv, nobv) -> {
                  logger.debug("Property changed {}: {}", it.getKey(), nobv);
                  p.setValue(String.valueOf(nobv));
                  toggle(false);
                });
            it.setValue(it.getValue() + " ");
            propertySheet.addItem(it);
          }
        }
        toggle(false);
      });

    } catch (Exception e) {
      logger.error("", e);
      // e.printStackTrace();
    }
  }

  @FXML
  void toggleDebug(ActionEvent event) {
    logger.debug("Toggle debug.");
    if (modal.isShowing())
      modal.close();
    else
      modal.show();
  }

  @FXML
  void showSettings(ActionEvent event) {
    logger.debug("Show settings.");
    dialog.show();
  }

  void toggle(boolean ignoreRestrcitions) {
    ActionEvent event = new ActionEvent();
    if (cbAutoCrypt.isSelected() | ignoreRestrcitions) {
      if (rbAutoDecrypt.isSelected()) {
        decrypt(event);
      } else {
        encrypt(event);
      }
    }
  }

  @FXML
  void decrypt(ActionEvent event) {
    logger.debug("Decryption requested.");
    String in = textInput.getText();
    if (in != null && !in.isEmpty() && cryptor != null) {

      Optional<?> optInfo = algorithms.stream()
          .filter((p) -> p.getName().equals(comboAlgo.getSelectionModel().getSelectedItem()))
          .findFirst();
      if (optInfo.isPresent()) {
        AlgoInfo info = (AlgoInfo) optInfo.get();
        for (AlgoProperty p : info.getProperties()) {
          cryptor.setProperty(p.getKey(), p.getValue());
        }
      }

      try {
        textOutput.setText(new String(cryptor.execute(in.getBytes(), Mode.DECRYPT)));
      } catch (Exception e) {
        logger.error(e, e.getCause());
      }
    }
  }

  @FXML
  void encrypt(ActionEvent event) {
    logger.debug("Encryption requested.");
    String in = textInput.getText();
    if (in != null && !in.isEmpty() && cryptor != null) {
      Optional<?> optInfo = algorithms.stream()
          .filter((p) -> p.getName().equals(comboAlgo.getSelectionModel().getSelectedItem()))
          .findFirst();
      if (optInfo.isPresent()) {
        logger.debug("Encryptor found");
        AlgoInfo info = (AlgoInfo) optInfo.get();
        for (AlgoProperty p : info.getProperties()) {
          logger.debug("Set property {}", p);
          cryptor.setProperty(p.getKey(), p.getValue());
        }
      }

      try {
        textOutput.setText(new String(cryptor.execute(in.getBytes(), Mode.ENCRYPT)));
      } catch (Exception e) {
        logger.error(e, e.getCause());
      }
    }
  }

  @FXML
  void loadContent(ActionEvent event) {
    logger.debug("Crypting filecontent triggered");
    FileChooser fc = new FileChooser();

    fc.setTitle(bundle.getString("window.cryptfile.select"));
    File fileIn = fc.showOpenDialog(modal);
    if (fileIn == null) {
      return;
    }

    fc.setTitle(bundle.getString("window.cryptfile.select.out"));
    File fileOut = fc.showSaveDialog(modal);
    if (fileOut == null) {
      return;
    }

    try {
      byte[] bytesIn = Files.readAllBytes(fileIn.toPath()), bytesOut = null;
      if (bytesIn != null && cryptor != null) {
        Optional<?> optInfo = algorithms.stream()
            .filter((p) -> p.getName().equals(comboAlgo.getSelectionModel().getSelectedItem()))
            .findFirst();
        if (optInfo.isPresent()) {
          AlgoInfo info = (AlgoInfo) optInfo.get();
          for (AlgoProperty p : info.getProperties()) {
            cryptor.setProperty(p.getKey(), p.getValue());
          }
        }

        if (rbAutoDecrypt.isSelected()) {
          bytesOut = cryptor.execute(bytesIn, Mode.DECRYPT);
        } else {
          bytesOut = cryptor.execute(bytesIn, Mode.ENCRYPT);
        }
      }

      if (bytesOut != null) {
        fileOut.delete();
        Files.write(fileOut.toPath(), bytesOut, StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
      }
    } catch (Exception e) {
      logger.error("Unable to crypt file", e);
    }
  }

  @FXML
  void close(ActionEvent event) {
    Platform.exit();
  }

}
