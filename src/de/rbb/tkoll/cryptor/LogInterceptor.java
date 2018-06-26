package de.rbb.tkoll.cryptor;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

@Plugin(name = "LogInterceptor", category = "Core", elementType = "appender", printObject = true)
public class LogInterceptor extends AbstractAppender {

  /**
   * 
   * @param lvl Integer representation of the level
   * @return The integer representation of the given log level (Integer.MAX_VALUE if unable to parse
   *         the lvl)
   */
  public static Level parseLevel(int lvl) {
    for (Level lev : Level.values()) {
      if (lev.intLevel() == lvl) {
        return lev;
      }
    }
    return Level.ALL;
  }
  /**
   * The minimum Level to register by this Appender. Not used atm.
   */
  @SuppressWarnings("unused")
  private Level                       minLevel;
  /**
   * Filepath for the logfile.
   */
  private final String                logfile;

  private final boolean               writeLogfile, appendConsole;
  /**
   * The StringProperty all logs get written to.
   */
  private static final StringProperty LogProperty = new SimpleStringProperty("");

  /**
   * 
   * @return The StringProperty all logs get written to.
   */
  public static StringProperty logProperty() {
    return LogProperty;
  }

  /**
   * Construct a new instance of the CustomAppender
   * 
   * @param name The Appender name.
   * @param filter The Filter to associate with the Appender.
   * @param layout The layout to use to format the event.
   * @param ignoreExceptions If true, exceptions will be logged and suppressed. If false errors will
   *        be logged and then passed to the application.
   */
  protected LogInterceptor(String name, Filter filter, Layout<? extends Serializable> layout,
      boolean ignoreExceptions) {
    this(name, filter, layout, ignoreExceptions, Level.ALL, true, true);
  }

  /**
   * Construct a new instance of the CustomAppender
   * 
   * @param name The Appender name.
   * @param filter The Filter to associate with the Appender.
   * @param layout The layout to use to format the event.
   * @param ignoreExceptions If true, exceptions will be logged and suppressed. If false errors will
   *        be logged and then passed to the application.
   * @param minlvl Minimum Level to log
   */
  protected LogInterceptor(String name, Filter filter, Layout<? extends Serializable> layout,
      boolean ignoreExceptions, final Level minlvl, boolean writeLogfile, boolean appendConsole) {
    super(name, filter, layout, ignoreExceptions);
    this.minLevel = minlvl;
    this.appendConsole = appendConsole;
    this.writeLogfile = writeLogfile;
    logfile = System.getProperty("user.home") + File.separator + "Cryptor.log";
  }

  @PluginFactory
  public static LogInterceptor createAppender(@PluginAttribute("name") String name,
      @PluginElement("Layout") Layout<? extends Serializable> layout,
      @PluginElement("Filter") final Filter filter,
      @PluginAttribute("minlevel") final String minlevel,
      @PluginAttribute("appendConsole") final Boolean appendConsole,
      @PluginAttribute("writeLogfile") final Boolean writeLogfile) {
    if (name == null) {
      LOGGER.error("No name provided for CustomAppender LogInterceptor");
      return null;
    }
    if (layout == null) {
      layout = PatternLayout.createDefaultLayout();
    }
    return new LogInterceptor(name, filter, layout, true, Level.valueOf(minlevel),
        appendConsole == true, writeLogfile == true);
  }

  @Override
  public synchronized void append(final LogEvent event) {
    byte[] byteArray = getLayout().toByteArray(event);
    final String logMsg = new String(byteArray);
    if (logfile != null && writeLogfile) {
      try {
        Files.write(new File(logfile).toPath(), byteArray, StandardOpenOption.APPEND,
            StandardOpenOption.CREATE);
      } catch (IOException e) {
        System.err.println(e);
      }
    }
    if (appendConsole) {
      System.out.print(logMsg);
    }
    logProperty().setValue(logMsg + LogProperty.getValue());
  }

}
