package de.rbb.tkoll.cryptor;

import java.io.IOException;
import java.io.InputStream;
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
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextArea;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToolBar;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class UIController extends GridPane {

  private final Logger             logger = LogManager.getLogger(getClass());

  @FXML
  private ResourceBundle           resources;
  @FXML
  private MenuBar                  menuBar;
  @FXML
  private Menu                     menuApp;
  @FXML
  private MenuItem                 menuItemClose, menuItemSettings, menuItemDebug;
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
    dialog.getDialogPane().getButtonTypes().addAll(ButtonType.APPLY, ButtonType.CANCEL);
    /*
     * Build the ui to show logger optput
     */
    TextArea debugTextArea = new TextArea();
    debugTextArea.textProperty().bind(LogInterceptor.logProperty());
    debugTextArea.setEditable(false);
    modal = new Stage();
    modal.setOnCloseRequest((val) -> modal.close());
    VBox modalVBox = new VBox();
    JFXButton modalCloseBtn = new JFXButton(resources.getString("common.close"));
    modalCloseBtn.setOnAction((v) -> modal.close());
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
      propertySheet.setTooltip(new Tooltip(resources.getString("tooltip.properties")));
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
      Gson gson = new Gson();
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

      System.out.println(algorithms.get(0).getClass());
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
    logger.debug("Opening filecontent triggered.");
  }

  @FXML
  void close(ActionEvent event) {
    Platform.exit();
  }

}
