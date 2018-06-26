package de.rbb.tkoll.cryptor.crypt;

import java.util.Arrays;
import java.util.List;

public class AlgoInfo {

  @Override
  public String toString() {
    return "AlgoInfo [name=" + name + ", properties=" + properties + "]";
  }

  public class AlgoProperty {

    @Override
    public String toString() {
      return "AlgoProperty [key=" + key + ", name=" + name + ", description=" + description
          + ", type=" + type + ", defaultValues=" + Arrays.toString(defaultValues) + ", validation="
          + validation + ", value=" + value + "]";
    }

    private String   key;
    private String   name;
    private String   description;
    private String   type;
    private String[] defaultValues;
    private String   validation;

    public String getValidation() {
      return validation;
    }

    public void setValidation(String validation) {
      this.validation = validation;
    }

    private String value;

    public String getKey() {
      return key;
    }

    public void setKey(String key) {
      this.key = key;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getDescription() {
      return description;
    }

    public void setDescription(String description) {
      this.description = description;
    }

    public String getType() {
      return type;
    }

    public void setType(String type) {
      this.type = type;
    }

    public String[] getDefaultValues() {
      return defaultValues;
    }

    public void setDefaultValues(String[] defaultValues) {
      this.defaultValues = defaultValues;
    }

    public String getValue() {
      return this.value;
    }

    public void setValue(String value) {
      this.value = value;
    }
  }

  private String             name;

  private List<AlgoProperty> properties;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public List<AlgoProperty> getProperties() {
    return properties;
  }

  protected void setProperties(List<AlgoProperty> properties) {
    this.properties = properties;
  }

  public AlgoProperty getProperty(String key) {
    for (AlgoProperty p : getProperties()) {
      if (p.getKey().equals(key)) {
        return p;
      }
    }

    return null;
  }

}
