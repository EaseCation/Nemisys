package org.itxtech.nemisys;

import com.google.common.base.Preconditions;
import io.netty.util.ResourceLeakDetector;
import io.netty.util.internal.logging.InternalLoggerFactory;
import io.netty.util.internal.logging.Log4J2LoggerFactory;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import lombok.extern.log4j.Log4j2;
import lombok.val;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.itxtech.nemisys.network.protocol.mcpe.ProtocolInfo;
import org.itxtech.nemisys.utils.ServerKiller;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Locale;
import java.util.Properties;

@Log4j2
public class Nemisys {

    public final static Properties GIT_INFO = getGitInfo();
    public final static String VERSION = getVersion();
    public final static String API_VERSION = "1.0.6";//majorVersion.minorVersion.sppVersion
    public final static String CODENAME = "Aegis";

    @Deprecated
    public final static String MINECRAFT_VERSION = ProtocolInfo.MINECRAFT_VERSION;

    @Deprecated
    public final static String MINECRAFT_VERSION_NETWORK = ProtocolInfo.MINECRAFT_VERSION_NETWORK;

    public final static String PATH = System.getProperty("user.dir") + "/";
    public final static String DATA_PATH = System.getProperty("user.dir") + "/";
    public final static String PLUGIN_PATH = DATA_PATH + "plugins";
    public static final long START_TIME = System.currentTimeMillis();
    public static boolean ANSI = true;
    public static boolean TITLE = false;
    public static boolean shortTitle = requiresShortTitle();
    public static int DEBUG = 1;

    static volatile boolean STOPPED;

    public static void main(String[] args) {
        Locale.setDefault(Locale.ENGLISH);

        System.setProperty("java.net.preferIPv4Stack" , "true");
        System.setProperty("log4j.skipJansi", "false");
        System.getProperties().putIfAbsent("io.netty.allocator.type", "unpooled"); // Disable memory pooling unless specified

        // DO NOT REMOVE THIS
        removeJceLimit();

        // Netty logger for debug info
        InternalLoggerFactory.setDefaultFactory(Log4J2LoggerFactory.INSTANCE);
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.DISABLED);

        // Define args
        OptionParser parser = new OptionParser();
        parser.allowsUnrecognizedOptions();
        OptionSpec<Void> helpSpec = parser.accepts("help", "Shows this page").forHelp();
        OptionSpec<Void> ansiSpec = parser.accepts("disable-ansi", "Disables console coloring");
        OptionSpec<Void> titleSpec = parser.accepts("enable-title", "Enables title at the top of the window");
        OptionSpec<String> vSpec = parser.accepts("v", "Set verbosity of logging").withRequiredArg().ofType(String.class);
        OptionSpec<String> verbositySpec = parser.accepts("verbosity", "Set verbosity of logging").withRequiredArg().ofType(String.class);

        // Parse arguments
        OptionSet options = parser.parse(args);

        if (options.has(helpSpec)) {
            try {
                // Display help page
                parser.printHelpOn(System.out);
            } catch (IOException e) {
                // ignore
            }
            return;
        }

        ANSI = !options.has(ansiSpec);
        TITLE = options.has(titleSpec);

        String verbosity = options.valueOf(vSpec);
        if (verbosity == null) {
            verbosity = options.valueOf(verbositySpec);
        }
        if (verbosity != null) {
            try {
                Level level = Level.valueOf(verbosity);
                setLogLevel(level);
            } catch (Exception e) {
                // ignore
            }
        }

        try {
            if (TITLE) {
                System.out.print((char) 0x1b + "]0;Starting Nemisys for Synapse Client" + (char) 0x07);
            }
            Server server = new Server(PATH, DATA_PATH, PLUGIN_PATH);
        } catch (Throwable t) {
            log.throwing(t);
        }

        for (Runnable listener : Server.SHUTDOWN_LISTENERS) {
            try {
                listener.run();
            } catch (Throwable e) {
                log.throwing(e);
            }
        }

        if (TITLE) {
            System.out.print((char) 0x1b + "]0;Stopping Server..." + (char) 0x07);
        }
        log.info("Stopping other threads");

        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (!(thread instanceof InterruptibleThread)) {
                continue;
            }
            log.debug("Stopping {} thread", thread.getClass().getSimpleName());
            if (thread.isAlive()) {
                thread.interrupt();
            }
        }

        LogManager.shutdown();

        ServerKiller killer = new ServerKiller(8);
        killer.start();

        if (TITLE) {
            System.out.print((char) 0x1b + "]0;Server Stopped" + (char) 0x07);
        }

        if (Boolean.getBoolean("nemisys.docker")) {
            System.out.println("Nemisys has exited.");
        }
        STOPPED = true;

        System.exit(0);
    }

    private static boolean requiresShortTitle() {
        //Shorter title for windows 8/2012/10
        String osName = System.getProperty("os.name").toLowerCase();
        return osName.contains("windows") && (osName.contains("windows 8") || osName.contains("2012") || osName.contains("10"));
    }

    private static Properties getGitInfo() {
        InputStream gitFileStream = Nemisys.class.getClassLoader().getResourceAsStream("git.properties");
        if (gitFileStream == null) {
            return null;
        }
        Properties properties = new Properties();
        try {
            properties.load(gitFileStream);
        } catch (IOException e) {
            return null;
        }
        return properties;
    }

    private static String getVersion() {
        StringBuilder version = new StringBuilder();
        version.append("1.0dev git-");
        String commitId;
        if (GIT_INFO == null || (commitId = GIT_INFO.getProperty("git.commit.id.abbrev")) == null) {
            return version.append("null").toString();
        }
        return version.append(commitId).toString();
    }

    public static void setLogLevel(Level level) {
        Preconditions.checkNotNull(level, "level");
        val context = LogManager.getContext(false);
        if (!(context instanceof LoggerContext)) {
            return;
        }
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration log4jConfig = ctx.getConfiguration();
        LoggerConfig loggerConfig = log4jConfig.getLoggerConfig(org.apache.logging.log4j.LogManager.ROOT_LOGGER_NAME);
        loggerConfig.setLevel(level);
        ctx.updateLoggers();
    }

    /**
     * 网易机子提供的是 Oracle JDK (8u144), 需要特殊处理.
     */
    private static void removeJceLimit() {
        try {
            Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            field.setAccessible(true);

            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

            field.set(null, false);
        } catch (Throwable ignored) {
            // 其它环境比如开发时用的 Open JDK 不需要
        }
    }
}
