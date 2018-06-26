package de.rbb.tkoll.cryptor;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Pattern;
import org.controlsfx.control.PropertySheet;
import org.controlsfx.property.editor.Editors;
import org.controlsfx.property.editor.PropertyEditor;
import org.reactfx.EventStreams;
import javafx.beans.property.Property;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.beans.value.ObservableValue;
import javafx.scene.control.TextField;
import javafx.scene.paint.Color;

/**
 * @author T Koll
 * @see
 * 
 *      <a href=
 *      "https://stackoverflow.com/questions/24238858/property-sheet-example-with-use-of-a-propertyeditor-controlsfx"/>
 *      StackOverflow-post that helped alot.
 */

public class GenericPropertySheet extends PropertySheet {
  public enum EditorType {
    AUTO, CHOICE, FILELIST

  }

  /**
   * 
   * @author T Koll
   *
   */
  public static class CustomItem implements PropertySheet.Item {
    private final StringProperty   group;
    private final StringProperty   name;
    private final Property<Object> value;
    private final StringProperty   descr;
    private volatile String        regex;
    private Class<?>               propertyClass;
    private EditorType             inputType;
    private String[]               choices;

    public String[] getChoices() {
      return choices;
    }

    public void setChoices(String[] choices) {
      this.choices = choices;
    }

    private final String key;

    public CustomItem(final String key, final String name, final String group, final String regex,
        final Object value, EditorType inputType) {
      super();
      this.key = key;
      this.group = new SimpleStringProperty(group);
      this.name = new SimpleStringProperty(name);
      this.value = new SimpleObjectProperty<>(value);
      this.descr = new SimpleStringProperty();
      this.regex = regex;
      this.inputType = inputType;
      if (value != null) {
        this.propertyClass = value.getClass();
      } else {
        this.propertyClass = Object.class;
      }
    }

    public String getKey() {
      return key;
    }

    public EditorType getInputType() {
      return inputType;
    }

    public void setInputType(EditorType inputType) {
      this.inputType = inputType;
    }

    @Override
    public Class<?> getType() {
      return this.propertyClass;
    }

    @Override
    public String getCategory() {
      return this.group.get();
    }

    @Override
    public String getName() {
      return this.name.get();
    }

    @Override
    public String getDescription() {
      return this.descr.get();
    }

    @Override
    public Object getValue() {
      return this.value.getValue();
    }

    @Override
    public void setValue(Object value) {
      if (propertyClass.isInstance(value)) {
        try {
          this.value.setValue(propertyClass.cast(value));
        } catch (Exception e) {
          this.setValue(value);
        }
      } else if (value != null) {
        this.propertyClass = value.getClass();
        this.setValue(value);
      } else if (value == null) {
        this.value.setValue(null);
      }
    }

    public <T> Optional<T> getTypedValue(final Class<T> clazz) {
      T value;
      try {
        value = clazz.cast(this.value.getValue());
      } catch (Exception e) {
        value = null;
      }
      return Optional.ofNullable(value);
    }

    @Override
    public Optional<ObservableValue<? extends Object>> getObservableValue() {
      return Optional.ofNullable(this.value);
    }

    public String getValidationRegex() {
      return this.regex;
    }

    public void setValidationRegex(String regex) {
      this.regex = regex;
    }
  }

  public <T> void addItem(final String key, final String name, final String group,
      final String descr, final String regex, final T value, EditorType inputType,
      String[] choices) {
    final Optional<CustomItem> item = getItem(key);
    final CustomItem it;
    if (item.isPresent()) {
      it = item.get();
      final int idx = this.getItems().indexOf(it);
      it.setValue(value);
      it.descr.set(descr);
      it.group.set(group);
      it.name.set(name);
      it.inputType = inputType;
      it.choices = choices;
      this.getItems().set(idx, it);
    } else {
      it = new CustomItem(key, name, group, regex, value, inputType);
      it.choices = choices;
      it.descr.set(descr);
      this.getItems().add(it);
    }
  }

  public void addItem(CustomItem item) {
    final Optional<CustomItem> oit = getItem(item.getKey());
    final CustomItem it;
    if (oit.isPresent()) {
      it = oit.get();
      final int idx = this.getItems().indexOf(it);
      it.setValue(item.value);
      it.descr.set(item.descr.get());
      it.group.set(item.group.get());
      it.name.set(item.name.get());
      it.inputType = item.inputType;
      this.getItems().set(idx, it);
    } else {
      this.getItems().add(item);
    }
  }

  public <T> void addItem(final String key, final String name, final String group,
      final String descr, final String regex, final T value, EditorType inputType) {
    final Optional<CustomItem> item = getItem(key);
    final CustomItem it;
    if (item.isPresent()) {
      it = item.get();
      final int idx = this.getItems().indexOf(it);
      it.setValue(value);
      it.descr.set(descr);
      it.group.set(group);
      it.name.set(name);
      it.inputType = inputType;
      this.getItems().set(idx, it);
    } else {
      it = new CustomItem(key, name, group, regex, value, inputType);
      it.descr.set(descr);
      this.getItems().add(it);
    }
  }

  public void removeItem(final String name) {
    this.getItems().removeIf(it -> name.equals(it.getName()));
  }

  public Optional<CustomItem> getItem(final String key) {
    return this.getItems().stream().filter((it) -> key.equals(((CustomItem) it).getKey()))
        .map(el -> (CustomItem) el).findFirst();
  }

  public <T> void setItem(final String key, final T value) {
    Optional<CustomItem> item = getItem(key);
    if (item.isPresent()) {
      item.get().setValue(value);
    }
  }

  public void setItemGroup(final String key, final String group) {
    Optional<CustomItem> item = getItem(key);
    if (item.isPresent()) {
      item.get().group.set(group);
    }
  }

  public GenericPropertySheet() {
    this.setPropertyEditorFactory(param -> {
      final Object value = param.getValue();
      CustomItem item = (CustomItem) param;
      final String rgx = item.getValidationRegex();
      if (value != null) {
        final Class<? extends Object> type = value.getClass();
        if (isNumber(type)) {
          return Editors.createNumericEditor(item);
        } else if (value instanceof Boolean || type == boolean.class) {
          return Editors.createCheckEditor(item);
        } else if (type.isAssignableFrom(Color.class)) {
          return Editors.createColorEditor(item);
        } else if (type.isEnum()) {
          return Editors.createChoiceEditor(item, Arrays.asList(type.getEnumConstants()));
        } else if (item.inputType == EditorType.CHOICE && item.choices != null) {
          return Editors.createChoiceEditor(item, Arrays.asList(item.choices));
        } else if (item.inputType == EditorType.FILELIST) {
        }
      }
      PropertyEditor<?> editor = Editors.createTextEditor(param);
      if (rgx != null) {
        addValidator(rgx, (TextField) editor.getEditor());
      }
      return editor;
    });
  }

  /**
   * Will set the textFields text-fill red if invalid, green if valid or black if empty.
   * 
   * @param regex Regular expression the input has to match.
   * @param target The textField to add validation to.
   */
  public static void addValidator(final String regex, final TextField target) {
    final Pattern p = Pattern.compile(regex);
    EventStreams.valuesOf(target.textProperty()).successionEnds(Duration.ofMillis(250))
        .subscribe((value) -> {
          if (value != null && !value.isEmpty()) {
            if (p.matcher(value).matches()) {
              target.setStyle("-fx-text-fill: green;");
            } else {
              target.setStyle("-fx-text-fill: red;");
            }
          } else {
            target.setStyle("-fx-text-fill: black;");
          }
        });
  }

  /**
   * Array containing Java's numeric types.
   */
  public static final Class<?>[] NumericTypes = new Class[] {byte.class, Byte.class, short.class,
      Short.class, int.class, Integer.class, long.class, Long.class, float.class, Float.class,
      double.class, Double.class, BigInteger.class, BigDecimal.class

  };

  /**
   * {@linkplain #NumericTypes}
   * 
   * @param type A type to check.
   * @return <code>true</code> if and only if the given type is a default numeric type.
   */
  public static boolean isNumber(Class<?> type) {
    if (type == null)
      return false;
    for (Class<?> cls : NumericTypes) {
      if (type == cls)
        return true;
    }
    return false;

  }

}
