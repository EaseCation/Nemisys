package org.itxtech.nemisys.plugin;

import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.utils.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;

/**
 * @author MagicDroidX
 * Nukkit Project
 */
public final class PluginLogger implements Logger, org.itxtech.nemisys.utils.Logger {

    private final Logger logger;
    private final String pluginName;

    public PluginLogger(Plugin context) {
        String prefix = context.getDescription().getPrefix();
        this.pluginName = prefix != null ? "[" + prefix + "] " : "[" + context.getDescription().getName() + "] ";
        this.logger = LoggerFactory.getLogger(context.getDescription().getFullName());
    }

    @Override
    public String getName() {
        return this.logger.getName();
    }

    @Override
    public boolean isTraceEnabled() {
        return this.logger.isTraceEnabled();
    }

    @Override
    public void trace(String message) {
        this.logger.trace(this.pluginName + message);
    }

    @Override
    public void trace(String format, Object argument) {
        this.logger.trace(this.pluginName + format, argument);
    }

    @Override
    public void trace(String format, Object firstArgument, Object secondArgument) {
        this.logger.trace(this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void trace(String format, Object... arguments) {
        this.logger.trace(this.pluginName + format, arguments);
    }

    @Override
    public void trace(String message, Throwable throwable) {
        this.logger.trace(this.pluginName + message, throwable);
    }

    @Override
    public boolean isTraceEnabled(Marker marker) {
        return this.logger.isTraceEnabled(marker);
    }

    @Override
    public void trace(Marker marker, String message) {
        this.logger.trace(marker, this.pluginName + message);
    }

    @Override
    public void trace(Marker marker, String format, Object argument) {
        this.logger.trace(marker, this.pluginName + format, argument);
    }

    @Override
    public void trace(Marker marker, String format, Object firstArgument, Object secondArgument) {
        this.logger.trace(marker, this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void trace(Marker marker, String format, Object... arguments) {
        this.logger.trace(marker, this.pluginName + format, arguments);
    }

    @Override
    public void trace(Marker marker, String message, Throwable throwable) {
        this.logger.trace(marker, this.pluginName + message, throwable);
    }

    @Override
    public boolean isDebugEnabled() {
        return this.logger.isDebugEnabled();
    }

    @Override
    public void debug(String message) {
        this.logger.debug(this.pluginName + message);
    }

    @Override
    public void debug(String format, Object argument) {
        this.logger.debug(this.pluginName + format, argument);
    }

    @Override
    public void debug(String format, Object firstArgument, Object secondArgument) {
        this.logger.debug(this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void debug(String format, Object... arguments) {
        this.logger.debug(this.pluginName + format, arguments);
    }

    @Override
    public void debug(String message, Throwable throwable) {
        this.logger.debug(this.pluginName + message, throwable);
    }

    @Override
    public boolean isDebugEnabled(Marker marker) {
        return this.logger.isDebugEnabled(marker);
    }

    @Override
    public void debug(Marker marker, String message) {
        this.logger.debug(marker, this.pluginName + message);
    }

    @Override
    public void debug(Marker marker, String format, Object argument) {
        this.logger.debug(marker, this.pluginName + format, argument);
    }

    @Override
    public void debug(Marker marker, String format, Object firstArgument, Object secondArgument) {
        this.logger.debug(marker, this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void debug(Marker marker, String format, Object... arguments) {
        this.logger.debug(marker, this.pluginName + format, arguments);
    }

    @Override
    public void debug(Marker marker, String message, Throwable throwable) {
        this.logger.debug(marker, this.pluginName + message, throwable);
    }

    @Override
    public boolean isInfoEnabled() {
        return this.logger.isInfoEnabled();
    }

    @Override
    public void info(String message) {
        this.logger.info(this.pluginName + message);
    }

    @Override
    public void info(String format, Object argument) {
        this.logger.info(this.pluginName + format, argument);
    }

    @Override
    public void info(String format, Object firstArgument, Object secondArgument) {
        this.logger.info(this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void info(String format, Object... arguments) {
        this.logger.info(this.pluginName + format, arguments);
    }

    @Override
    public void info(String message, Throwable throwable) {
        this.logger.info(this.pluginName + message, throwable);
    }

    @Override
    public boolean isInfoEnabled(Marker marker) {
        return this.logger.isInfoEnabled(marker);
    }

    @Override
    public void info(Marker marker, String message) {
        this.logger.info(marker, this.pluginName + message);
    }

    @Override
    public void info(Marker marker, String format, Object argument) {
        this.logger.info(marker, this.pluginName + format, argument);
    }

    @Override
    public void info(Marker marker, String format, Object firstArgument, Object secondArgument) {
        this.logger.info(marker, this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void info(Marker marker, String format, Object... arguments) {
        this.logger.info(marker, this.pluginName + format, arguments);
    }

    @Override
    public void info(Marker marker, String message, Throwable throwable) {
        this.logger.info(marker, this.pluginName + message, throwable);
    }

    @Override
    public boolean isWarnEnabled() {
        return this.logger.isWarnEnabled();
    }

    @Override
    public void warn(String message) {
        this.logger.warn(this.pluginName + message);
    }

    @Override
    public void warn(String format, Object argument) {
        this.logger.warn(this.pluginName + format, argument);
    }

    @Override
    public void warn(String format, Object firstArgument, Object secondArgument) {
        this.logger.warn(this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void warn(String format, Object... arguments) {
        this.logger.warn(this.pluginName + format, arguments);
    }

    @Override
    public void warn(String message, Throwable throwable) {
        this.logger.warn(this.pluginName + message, throwable);
    }

    @Override
    public boolean isWarnEnabled(Marker marker) {
        return this.logger.isWarnEnabled(marker);
    }

    @Override
    public void warn(Marker marker, String message) {
        this.logger.warn(marker, this.pluginName + message);
    }

    @Override
    public void warn(Marker marker, String format, Object argument) {
        this.logger.warn(marker, this.pluginName + format, argument);
    }

    @Override
    public void warn(Marker marker, String format, Object firstArgument, Object secondArgument) {
        this.logger.warn(marker, this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void warn(Marker marker, String format, Object... arguments) {
        this.logger.warn(marker, this.pluginName + format, arguments);
    }

    @Override
    public void warn(Marker marker, String message, Throwable throwable) {
        this.logger.warn(marker, this.pluginName + message, throwable);
    }

    @Override
    public boolean isErrorEnabled() {
        return this.logger.isErrorEnabled();
    }

    @Override
    public void error(String message) {
        this.logger.error(this.pluginName + message);
    }

    @Override
    public void error(String format, Object argument) {
        this.logger.error(this.pluginName + format, argument);
    }

    @Override
    public void error(String format, Object firstArgument, Object secondArgument) {
        this.logger.error(this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void error(String format, Object... arguments) {
        this.logger.error(this.pluginName + format, arguments);
    }

    @Override
    public void error(String message, Throwable throwable) {
        this.logger.error(this.pluginName + message, throwable);
    }

    @Override
    public boolean isErrorEnabled(Marker marker) {
        return this.logger.isErrorEnabled(marker);
    }

    @Override
    public void error(Marker marker, String message) {
        this.logger.error(marker, this.pluginName + message);
    }

    @Override
    public void error(Marker marker, String format, Object argument) {
        this.logger.error(marker, this.pluginName + format, argument);
    }

    @Override
    public void error(Marker marker, String format, Object firstArgument, Object secondArgument) {
        this.logger.error(marker, this.pluginName + format, firstArgument, secondArgument);
    }

    @Override
    public void error(Marker marker, String format, Object... arguments) {
        this.logger.error(marker, this.pluginName + format, arguments);
    }

    @Override
    public void error(Marker marker, String message, Throwable throwable) {
        this.logger.error(marker, this.pluginName + message, throwable);
    }

    @Override
    public void emergency(String message) {
        this.logger.error(this.pluginName + message);
    }

    @Override
    public void alert(String message) {
        this.logger.warn(this.pluginName + message);
    }

    @Override
    public void critical(String message) {
        this.logger.error(this.pluginName + message);
    }

    @Override
    public void warning(String message) {
        this.logger.warn(this.pluginName + message);
    }

    @Override
    public void notice(String message) {
        this.logger.warn(this.pluginName + message);
    }

    @Override
    public void log(LogLevel level, String message) {
        Server.getInstance().getLogger().log(level, this.pluginName + message);
    }

    @Override
    public void emergency(String message, Throwable throwable) {
        this.logger.error(this.pluginName + message, throwable);
    }

    @Override
    public void alert(String message, Throwable throwable) {
        this.logger.warn(this.pluginName + message, throwable);
    }

    @Override
    public void critical(String message, Throwable throwable) {
        this.logger.error(this.pluginName + message, throwable);
    }

    @Override
    public void warning(String message, Throwable throwable) {
        this.logger.warn(this.pluginName + message, throwable);
    }

    @Override
    public void notice(String message, Throwable throwable) {
        this.logger.warn(this.pluginName + message, throwable);
    }

    @Override
    public void log(LogLevel level, String message, Throwable throwable) {
        Server.getInstance().getLogger().log(level, this.pluginName + message, throwable);
    }
}
