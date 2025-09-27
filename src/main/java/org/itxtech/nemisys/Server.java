package org.itxtech.nemisys;

import com.dosse.upnp.UPnP;
import com.google.common.base.Preconditions;
import io.netty.buffer.ByteBuf;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import it.unimi.dsi.fastutil.objects.ObjectArrayList;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.Level;
import org.itxtech.nemisys.command.*;
import org.itxtech.nemisys.console.NemisysConsole;
import org.itxtech.nemisys.data.ServerConfiguration;
import org.itxtech.nemisys.event.HandlerList;
import org.itxtech.nemisys.lang.TranslationContainer;
import org.itxtech.nemisys.event.server.QueryRegenerateEvent;
import org.itxtech.nemisys.lang.BaseLang;
import org.itxtech.nemisys.math.Mth;
import org.itxtech.nemisys.math.NemisysMath;
import org.itxtech.nemisys.network.*;
import org.itxtech.nemisys.network.protocol.mcpe.BatchPacket;
import org.itxtech.nemisys.network.protocol.mcpe.DataPacket;
import org.itxtech.nemisys.network.query.QueryHandler;
import org.itxtech.nemisys.network.rcon.RCON;
import org.itxtech.nemisys.plugin.JavaPluginLoader;
import org.itxtech.nemisys.plugin.Plugin;
import org.itxtech.nemisys.plugin.PluginLoadOrder;
import org.itxtech.nemisys.plugin.PluginManager;
import org.itxtech.nemisys.scheduler.ServerScheduler;
import org.itxtech.nemisys.synapse.Synapse;
import org.itxtech.nemisys.synapse.SynapseEntry;
import org.itxtech.nemisys.utils.*;
import org.itxtech.nemisys.utils.ClientData.Entry;
import org.itxtech.nemisys.utils.bugreport.ExceptionHandler;

import java.io.File;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.Deflater;

/**
 * author: MagicDroidX & Box
 * Nukkit
 */
@Log4j2
public class Server {
    public static final int TPS = 100;

    private static Server instance = null;
    private final AtomicBoolean isRunning = new AtomicBoolean(true);
    private volatile boolean hasStopped = false;
    @Getter
    private final ServerConfiguration configuration;
    private final PluginManager pluginManager;
    private final ServerScheduler scheduler;
    private int tickCounter;
    private long nextTick;
    private final float[] tickAverage = {100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100};
    private final float[] useAverage = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private float maxTick = 100;
    private float maxUse = 0;
    private final NemisysConsole console;
    private final ConsoleThread consoleThread;
    private final SimpleCommandMap commandMap;
    private final ConsoleCommandSender consoleSender;
    private final int maxPlayers;
    private RCON rcon;
    private final Network network;
    @Getter
    private final boolean networkEncryptionEnabled;
    @Getter
    private final int networkCompressionLevel;
    private final BaseLang baseLang;
    private final boolean forceLanguage = false;
    private final UUID serverID;
    private final String filePath;
    private final String dataPath;
    private final String pluginPath;
    private boolean upnpEnabled;
    private QueryHandler queryHandler;
    private QueryRegenerateEvent queryRegenerateEvent;
    private final Config properties;
    private final Map<InetSocketAddress, Player> players = new Object2ObjectOpenHashMap<>();
    private final SynapseInterface synapseInterface;
    private final Map<String, Client> clients = new Object2ObjectOpenHashMap<>();
    private ClientData clientData = new ClientData();
    private final Map<String, Client> mainClients = new Object2ObjectOpenHashMap<>();
    private Synapse synapse;
    private final Thread currentThread;
    private Watchdog watchdog;
    private final boolean enableJmxMonitoring;
    /**
     * 过去 100 tick 的耗时 (ns). 用于 JMX Monitoring.
     */
    public final long[] tickTimes = new long[100];
    /**
     * 过去 100 tick 的平均耗时 (ms). 用于 JMX Monitoring.
     */
    public float averageTickTime;

    static final List<Runnable> SHUTDOWN_LISTENERS = new ArrayList<>();

    public Server(final String filePath, String dataPath, String pluginPath) {
        Preconditions.checkState(instance == null, "Already initialized!");
        currentThread = Thread.currentThread();
        instance = this;

        this.filePath = filePath;

        if (!new File(pluginPath).exists()) {
            new File(pluginPath).mkdirs();
        }

        this.dataPath = new File(dataPath).getAbsolutePath() + "/";
        this.pluginPath = new File(pluginPath).getAbsolutePath() + "/";

        this.console = new NemisysConsole(this);
        this.consoleThread = new ConsoleThread();
        this.consoleThread.start();

        this.console.setExecutingCommands(true);

        log.info("Loading {} ...", TextFormat.GREEN + "server properties" + TextFormat.WHITE);
        this.properties = new Config(this.dataPath + "server.properties", Config.PROPERTIES, new ConfigSection() {
            {
                put("motd", "Nemisys Proxy");
                put("sub-motd", "Powered by Nemisys");
                put("server-ip", "0.0.0.0");
                put("server-port", 19132);
                put("synapse-ip", "0.0.0.0");
                put("synapse-port", 10305);
                put("password", "1234567890123456"/* TODO MD5 Password*/);
                put("lang", "eng");
                put("async-workers", "auto");
                put("enable-profiling", false);
                put("profile-report-trigger", 20);
                put("max-players", 20);
                put("plus-one-max-count", false);
                put("dynamic-player-count", false);
                put("enable-upnp", false);
                put("enable-query", true);
                put("enable-rcon", false);
                put("rcon.password", Base64.getEncoder().encodeToString(UUID.randomUUID().toString().replace("-", "").getBytes()).substring(3, 13));
                put("debug", 1);
                put("bug-report", true);
                put("enable-synapse-client", false);
                put("xbox-auth", true);
                put("enable-jmx-monitoring", false);
                put("enable-network-encryption", true);
                put("network-compression-level", 7);
                put("packet-recorder-capability", false);
            }
        });

        configuration = ServerConfiguration.builder()
                .serverIp(getPropertyString("server-ip", "0.0.0.0"))
                .serverPort(getPropertyInt("server-port", 19132))
                .password(getPropertyString("password", "1234567890123456"))
                .motd(getPropertyString("motd", "Nemisys Server"))
                .plusOneMaxCount(getPropertyBoolean("plus-one-max-count", false))
                .xboxAuth(getPropertyBoolean("xbox-auth", false))
                .build();

        this.baseLang = new BaseLang((String) this.getConfig("lang", BaseLang.FALLBACK_LANGUAGE));
        log.info(this.getLanguage().translateString("language.selected", new String[]{getLanguage().getName(), getLanguage().getLang()}));
        log.info(getLanguage().translateString("nemisys.server.start", TextFormat.AQUA + this.getVersion() + TextFormat.WHITE));

        int corePoolSize;
        Object poolSize = this.getProperty("async-workers", "auto");
        try {
            corePoolSize = Math.max(Integer.parseInt(String.valueOf(poolSize)), 0);
        } catch (Exception e) {
            corePoolSize = Math.max(Runtime.getRuntime().availableProcessors() + 1, 4);
        }
        int maximumPoolSize = this.getPropertyInt("max-async-workers", 0);
        if (maximumPoolSize > 0) {
            maximumPoolSize = Math.max(corePoolSize, maximumPoolSize);
        } else {
            maximumPoolSize = Integer.MAX_VALUE;
        }
        int keepAliveSeconds = this.getPropertyInt("async-worker-keep-alive", 60);
        log.info("AsyncPool Workers: minimum {} threads, maximum {} threads, keep alive {} seconds", corePoolSize, maximumPoolSize, keepAliveSeconds);

        Zlib.setProvider(2);

        this.scheduler = new ServerScheduler(corePoolSize, maximumPoolSize, keepAliveSeconds);

        if (this.getPropertyBoolean("enable-rcon", false)) {
            try {
                this.rcon = new RCON(this, this.getPropertyString("rcon.password", ""), !this.getIp().isEmpty() ? this.getIp() : "0.0.0.0", this.getPropertyInt("rcon.port", this.getPort()));
            } catch (IllegalArgumentException e) {
                log.error(getLanguage().translateString(e.getMessage(), e.getCause().getMessage()), e);
            }
        }

        this.maxPlayers = this.getPropertyInt("max-players", 20);

        Nemisys.DEBUG = Math.max(this.getPropertyInt("debug", 1), 1);

        int logLevel = (Nemisys.DEBUG + 3) * 100;
        for (Level level : Level.values()) {
            if (level.intLevel() == logLevel) {
                Nemisys.setLogLevel(level);
                break;
            }
        }

        if (this.getPropertyBoolean("bug-report", true)) {
            ExceptionHandler.registerExceptionHandler();
        }

        this.enableJmxMonitoring = this.getPropertyBoolean("enable-jmx-monitoring", false);
        if (this.enableJmxMonitoring) {
            ServerStatistics.registerJmxMonitoring(this);
        }

        log.info(this.getLanguage().translateString("nemisys.server.networkStart", new String[]{this.getIp().isEmpty() ? "*" : this.getIp(), String.valueOf(this.getPort())}));
        this.serverID = UUID.randomUUID();

        this.network = new Network(this);
        this.network.setName(this.getMotd());
        this.network.setSubName(this.getSubMotd());

        log.info(this.getLanguage().translateString("nemisys.server.info", new String[]{this.getName(), TextFormat.YELLOW + this.getNemisysVersion() + TextFormat.WHITE, TextFormat.AQUA + this.getCodename() + TextFormat.WHITE, this.getApiVersion()}));
        log.info(this.getLanguage().translateString("nemisys.server.license", this.getName()));

        this.consoleSender = new ConsoleCommandSender();
        this.commandMap = new SimpleCommandMap(this);

        this.pluginManager = new PluginManager(this, this.commandMap);
        this.pluginManager.registerInterface(JavaPluginLoader.class);
        this.queryRegenerateEvent = new QueryRegenerateEvent(this, 5);

        this.networkEncryptionEnabled = this.getPropertyBoolean("enable-network-encryption");
        this.networkCompressionLevel = Mth.clamp(this.getPropertyInt("network-compression-level", 7), Deflater.BEST_SPEED, Deflater.BEST_COMPRESSION);

        Capabilities.PACKET_RECORDER = this.getPropertyBoolean("packet-recorder-capability");

        if (!Boolean.getBoolean("nemisys.disableRak")) {
            this.network.registerInterface(new RakNetInterface(this));
        }

        this.synapseInterface = new SynapseInterface(this, this.getSynapseIp(), this.getSynapsePort());

        this.pluginManager.loadPlugins(this.pluginPath);
        this.enablePlugins(PluginLoadOrder.STARTUP);

        if (this.getPropertyBoolean("enable-synapse-client")) {
            try {
                this.synapse = new Synapse(this);
            } catch (Exception e) {
                log.warn("Failed.", e);
            }
        }

        this.properties.save(true);

        if (Nemisys.DEBUG < 2) {
            this.watchdog = new Watchdog(this, 60000);
            this.watchdog.start();
        }

        this.start();
    }

    public static Server getInstance() {
        return instance;
    }

    public static void broadcastPacket(Collection<Player> players, DataPacket packet) {
        broadcastPacket(players.toArray(new Player[0]), packet);
    }

    public static void broadcastPacket(Player[] players, DataPacket packet) {
        packet.encode();
        packet.isEncoded = true;

        for (Player player : players) {
            player.sendDataPacket(packet);
        }
    }

    public void addClient(Client client) {
        this.clients.put(client.getHash(), client);
        if (client.isMainServer()) {
            this.mainClients.put(client.getHash(), client);
        }
    }

    public Client getClient(String hash) {
        return this.clients.get(hash);
    }

    public Map<String, Client> getMainClients() {
        return this.mainClients;
    }

    public void removeClient(Client client) {
        if (this.clients.remove(client.getHash()) != null) {
            this.mainClients.remove(client.getHash());
        }
    }

    public Map<String, Client> getClients() {
        return this.clients;
    }

    public ClientData getClientData() {
        return clientData;
    }

    public void updateClientData() {
        if (!this.clients.isEmpty()) {
            ClientData clientData = new ClientData();
            for (Client client : this.clients.values()) {
                ClientData.Entry entry = new Entry(client.getIp(), client.getPort(), client.getPlayers().size(),
                        client.getMaxPlayers(), client.getDescription());
                clientData.clientList.put(client.getHash(), entry);
            }
            this.clientData = clientData;
        }
    }

    public boolean comparePassword(String pass) {
        String truePass = this.getConfiguration().getPassword();
        return truePass.equals(pass);
    }

    public void enablePlugins(PluginLoadOrder type) {
        for (Plugin plugin : this.pluginManager.getPlugins().values()) {
            if (!plugin.isEnabled() && type == plugin.getDescription().getOrder()) {
                this.enablePlugin(plugin);
            }
        }
    }

    public void enablePlugin(Plugin plugin) {
        this.pluginManager.enablePlugin(plugin);
    }

    public void disablePlugins() {
        this.pluginManager.disablePlugins();
    }

    public boolean dispatchCommand(CommandSender sender, String commandLine) throws ServerException {
        if (sender == null) {
            throw new ServerException("CommandSender is not valid");
        }

        if (this.commandMap.dispatch(sender, commandLine)) {
            return true;
        }

        sender.sendMessage(new TranslationContainer(TextFormat.RED + "%commands.generic.notFound"));

        return false;
    }

    //todo: use ticker to check console
    public ConsoleCommandSender getConsoleSender() {
        return consoleSender;
    }

    public void shutdown() {
        isRunning.compareAndSet(true, false);
    }

    public void forceShutdown() {
        if (this.hasStopped) {
            return;
        }

        try {
            isRunning.compareAndSet(true, false);

            this.hasStopped = true;

            if (this.rcon != null) {
                this.rcon.close();
            }

            String shutdownMessage = (String) this.getConfig("settings.shutdown-message", "Proxy closed");
            for (Client client : new ObjectArrayList<>(this.clients.values())) {
                for (Player player : new ObjectArrayList<>(client.getPlayers().values())) {
                    player.close(shutdownMessage);
                }
                client.close("Synapse server closed");
            }

            log.debug("Disabling all plugins");
            this.pluginManager.disablePlugins();

            log.debug("Removing event handlers");
            HandlerList.unregisterAll();

            log.debug("Stopping all tasks");
            this.scheduler.cancelAllTasks();
            this.scheduler.mainThreadHeartbeat(Integer.MAX_VALUE);

            log.debug("Closing console");
            this.consoleThread.interrupt();

            if (this.upnpEnabled) {
                log.debug("Closing UPnP port");
                if (UPnP.closePortUDP(this.getPort())) {
                    log.info("Removed forwarding rule for UDP Port {} using UPnP.", getPort());
                }
            }

            log.debug("Stopping network interfaces");
            for (SourceInterface interfaz : new ObjectArrayList<>(this.network.getInterfaces())) {
                interfaz.shutdown();
                this.network.unregisterInterface(interfaz);
            }
            if (this.synapse != null) {
                for (SynapseEntry entry : this.synapse.getSynapseEntries().values()) {
                    entry.getSynapseInterface().shutdown();
                }
            }
            this.synapseInterface.getInterface().shutdown();

            if (this.watchdog != null) {
                this.watchdog.kill();
            }
        } catch (Exception e) {
            log.fatal("Exception happened while shutting down", e);
        }
    }

    public void start() {
        if (this.getPropertyBoolean("enable-upnp", false)) {
            if (UPnP.isUPnPAvailable()) {
                log.debug("UPnP enabled. Attempting to port-forward with UPnP.");
                if (UPnP.openPortUDP(getPort(), "Nemisys")) {
                    this.upnpEnabled = true; // Saved to disable the port-forwarding on shutdown
                    log.info("Successfully forwarded UDP Port {} using UPnP.", getPort());
                } else {
                    this.upnpEnabled = false;
                    log.warn("Failed to forward UDP Port {} using UPnP.", getPort());
                }
            } else {
                this.upnpEnabled = false;
                log.warn("UPnP is enabled, but no UPnP enabled gateway was found.");
            }
        } else {
            this.upnpEnabled = false;
            log.debug("UPnP is disabled.");
        }

        if (this.getPropertyBoolean("enable-query", true)) {
            this.queryHandler = new QueryHandler();
        }

        this.tickCounter = 0;

        if (Boolean.getBoolean("nemisys.docker")) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                shutdown();

                System.out.println("Shutdown hook triggered...");
                while (!Nemisys.STOPPED) {
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                System.out.println("Server Stopped.");
            }, "Nemisys Shutdown Hook"));
        }

        log.info(this.getLanguage().translateString("nemisys.server.startFinished", String.valueOf((double) (System.currentTimeMillis() - Nemisys.START_TIME) / 1000)));

        this.tickProcessor();
        this.forceShutdown();
    }

    public void handlePacket(InetSocketAddress address, ByteBuf payload) {
        try {
            if (!payload.isReadable(3)) {
                return;
            }
            byte[] prefix = new byte[2];
            payload.readBytes(prefix);

            if (!Arrays.equals(prefix, new byte[]{(byte) 0xfe, (byte) 0xfd})) {
                return;
            }
            if (this.queryHandler != null) {
                this.queryHandler.handle(address, payload);
            }
        } catch (Exception e) {
            log.error("Error whilst handling packet", e);

            this.network.blockAddress(address.getAddress(), -1);
        }
    }

    public void tickProcessor() {
        this.nextTick = System.currentTimeMillis();
        try {
            while (this.isRunning.get()) {
                try {
                    this.tick();
                } catch (RuntimeException e) {
                    log.warn("tickProcessor ROOT RuntimeException", e);
                } finally {
                    long next = this.nextTick;
                    long current = System.currentTimeMillis();
                    if (next - 0.1 > current) {
                        Thread.sleep(next - current - 1, 900000);
                    }
                }
            }
        } catch (Throwable e) {
            log.fatal("Exception happened while ticking server", e);
            log.fatal(Utils.getAllThreadDumps());
        }
    }

    public void addPlayer(InetSocketAddress socketAddress, Player player) {
        this.players.put(socketAddress, player);
    }

    private boolean tick() {
        long tickTime = System.currentTimeMillis();
        long tickTimeNano = System.nanoTime();
        if ((tickTime - this.nextTick) < -5) {
            return false;
        }

        ++this.tickCounter;

        this.network.processInterfaces();
        this.synapseInterface.process();

        if (this.rcon != null) {
            this.rcon.check();
        }

        this.scheduler.mainThreadHeartbeat(this.tickCounter);

//        for (Player player : new ObjectArrayList<>(this.players.values())) {
//            player.onUpdate(this.tickCounter);
//        }

        for (Client client : new ObjectArrayList<>(this.clients.values())) {
            client.onUpdate(this.tickCounter);
        }

        if ((this.tickCounter & 0b1111) == 0) {
            this.titleTick();
            this.network.resetStatistics();
            this.maxTick = 100;
            this.maxUse = 0;

            if ((this.tickCounter & 0b111111111) == 0) {
                try {
                    this.getPluginManager().callEvent(this.queryRegenerateEvent = new QueryRegenerateEvent(this, 5));
                    if (this.queryHandler != null) {
                        this.queryHandler.regenerateInfo();
                    }
                } catch (Exception e) {
                    log.error(e);
                }
            }

            this.getNetwork().updateName();
        }

        //long now = System.currentTimeMillis();
        long nowNano = System.nanoTime();
        //float tick = Math.min(100, 1000 / Math.max(1, now - tickTime));
        //float use = Math.min(1, (now - tickTime) / 50);

        float tick = (float) Math.min(100, 1000000000 / Math.max(1000000, ((double) nowNano - tickTimeNano)));
        float use = (float) Math.min(1, ((double) (nowNano - tickTimeNano)) / 50000000);

        if (this.maxTick > tick) {
            this.maxTick = tick;
        }

        if (this.maxUse < use) {
            this.maxUse = use;
        }

        System.arraycopy(this.tickAverage, 1, this.tickAverage, 0, this.tickAverage.length - 1);
        this.tickAverage[this.tickAverage.length - 1] = tick;

        System.arraycopy(this.useAverage, 1, this.useAverage, 0, this.useAverage.length - 1);
        this.useAverage[this.useAverage.length - 1] = use;

        if (this.enableJmxMonitoring) {
            long diffNano = nowNano - tickTimeNano;
            this.tickTimes[this.tickCounter % 100] = diffNano;
            this.averageTickTime = this.averageTickTime * .8f + (float) diffNano / 1000000f * .19999999f;
        }

        if ((this.nextTick - tickTime) < -1000) {
            this.nextTick = tickTime;
        } else {
            this.nextTick += 10;
        }

        return true;
    }

    public long getNextTick() {
        return nextTick;
    }

    public void titleTick() {
        if (!Nemisys.ANSI || !Nemisys.TITLE) {
            return;
        }

        Runtime runtime = Runtime.getRuntime();
        double used = NemisysMath.round((double) (runtime.totalMemory() - runtime.freeMemory()) / 1024 / 1024, 2);
        double max = NemisysMath.round(((double) runtime.maxMemory()) / 1024 / 1024, 2);
        String usage = Math.round(used / max * 100) + "%";
        String title = (char) 0x1b + "]0;" + this.getName() + " " +
                this.getNemisysVersion() +
                " | Online " + this.players.size() + "/" + this.getMaxPlayers() +
                " | Clients " + this.clients.size() +
                " | Memory " + usage;
        if (!Nemisys.shortTitle) {
            title += " | U " + NemisysMath.round((this.network.getUpload() / 1024 * 1000), 2)
                    + " D " + NemisysMath.round((this.network.getDownload() / 1024 * 1000), 2) + " kB/s";

            if (this.synapseInterface.getInterface().getSessionManager() != null) {
                title += " | SynLibTPS " + this.synapseInterface.getInterface().getSessionManager().getTicksPerSecond() +
                        " | SynLibLoad " + this.synapseInterface.getInterface().getSessionManager().getTickUsage() + "%";
            }
        }

        title += " | TPS " + this.getTicksPerSecond() +
                " | Load " + this.getTickUsage() + "%" + (char) 0x07;

        System.out.print(title);
    }

    public QueryRegenerateEvent getQueryInformation() {
        return this.queryRegenerateEvent;
    }

    public String getName() {
        return "Nemisys";
    }

    public boolean isRunning() {
        return isRunning.get();
    }

    public String getNemisysVersion() {
        return Nemisys.VERSION;
    }

    public String getCodename() {
        return Nemisys.CODENAME;
    }

    public String getVersion() {
        return Nemisys.MINECRAFT_VERSION;
    }

    public String getApiVersion() {
        return Nemisys.API_VERSION;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getDataPath() {
        return dataPath;
    }

    public String getPluginPath() {
        return pluginPath;
    }

    public int getMaxPlayers() {
        return maxPlayers;
    }

    public int getPort() {
        return this.getConfiguration().getServerPort();
    }

    public String getIp() {
        return this.getConfiguration().getServerIp();
    }

    public int getSynapsePort() {
        return this.getPropertyInt("synapse-port", 10305);
    }

    public String getSynapseIp() {
        return this.getPropertyString("synapse-ip", "0.0.0.0");
    }

    public UUID getServerUniqueId() {
        return this.serverID;
    }

    public String getMotd() {
        return this.getConfiguration().getMotd();
    }

    public String getSubMotd() {
        String subMotd = this.getPropertyString("sub-motd", "Powered by Nemisys");
        if (subMotd.isEmpty()) {
            subMotd = "Powered by Nemisys"; // The client doesn't allow empty sub-motd in 1.16.210
        }
        return subMotd;
    }

    public MainLogger getLogger() {
        return MainLogger.getLogger();
    }

    public PluginManager getPluginManager() {
        return this.pluginManager;
    }

    public ServerScheduler getScheduler() {
        return scheduler;
    }

    public int getTick() {
        return tickCounter;
    }

    public float getTicksPerSecond() {
        return ((float) Math.round(this.maxTick * 100)) / 100;
    }

    public float getTicksPerSecondAverage() {
        float sum = 0;
        int count = this.tickAverage.length;
        for (float aTickAverage : this.tickAverage) {
            sum += aTickAverage;
        }
        return (float) NemisysMath.round(sum / count, 2);
    }

    public float getTickUsage() {
        return (float) NemisysMath.round(this.maxUse * 100, 2);
    }

    public float getTickUsageAverage() {
        float sum = 0;
        int count = this.useAverage.length;
        for (float aUseAverage : this.useAverage) {
            sum += aUseAverage;
        }
        return ((float) Math.round(sum / count * 100)) / 100;
    }

    public SimpleCommandMap getCommandMap() {
        return commandMap;
    }

    public Map<InetSocketAddress, Player> getOnlinePlayers() {
        return this.players;
    }

    public Player getPlayer(String name) {
        Player found = null;
        name = name.toLowerCase();
        int delta = Integer.MAX_VALUE;
        for (Player player : this.getOnlinePlayers().values()) {
            if (player.getName().toLowerCase().startsWith(name)) {
                int curDelta = player.getName().length() - name.length();
                if (curDelta < delta) {
                    found = player;
                    delta = curDelta;
                }
                if (curDelta == 0) {
                    break;
                }
            }
        }

        return found;
    }

    public Player getPlayerExact(String name) {
        name = name.toLowerCase();
        for (Player player : this.getOnlinePlayers().values()) {
            if (player.getName().toLowerCase().equals(name)) {
                return player;
            }
        }

        return null;
    }

    public Player[] matchPlayer(String partialName) {
        partialName = partialName.toLowerCase();
        List<Player> matchedPlayer = new ObjectArrayList<>();
        for (Player player : this.getOnlinePlayers().values()) {
            if (player.getName().toLowerCase().equals(partialName)) {
                return new Player[]{player};
            } else if (player.getName().toLowerCase().contains(partialName)) {
                matchedPlayer.add(player);
            }
        }

        return matchedPlayer.toArray(new Player[0]);
    }

    public void removePlayer(Player player) {
        Player toRemove = this.players.remove(player.getSocketAddress());
        if (toRemove != null) {
            return;
        }

        for (InetSocketAddress socketAddress : new ObjectArrayList<>(this.players.keySet())) {
            Player p = this.players.get(socketAddress);
            if (player == p) {
                this.players.remove(socketAddress);
                break;
            }
        }
    }

    public BaseLang getLanguage() {
        return baseLang;
    }

    public boolean isLanguageForced() {
        return forceLanguage;
    }

    public Network getNetwork() {
        return network;
    }

    public Object getConfig(String variable) {
        return this.getConfig(variable, null);
    }

    public Object getConfig(String variable, Object defaultValue) {
        Object value = this.properties.get(variable);
        return value == null ? defaultValue : value;
    }

    public Object getProperty(String variable) {
        return this.getProperty(variable, null);
    }

    public Object getProperty(String variable, Object defaultValue) {
        return this.properties.exists(variable) ? this.properties.get(variable) : defaultValue;
    }

    public void setPropertyString(String variable, String value) {
        this.properties.set(variable, value);
        this.properties.save();
    }

    public String getPropertyString(String variable) {
        return this.getPropertyString(variable, null);
    }

    public String getPropertyString(String variable, String defaultValue) {
        return this.properties.exists(variable) ? (String) this.properties.get(variable) : defaultValue;
    }

    public int getPropertyInt(String variable) {
        return this.getPropertyInt(variable, null);
    }

    public int getPropertyInt(String variable, Integer defaultValue) {
        return this.properties.exists(variable) ? (!this.properties.get(variable).equals("") ? Integer.parseInt(String.valueOf(this.properties.get(variable))) : defaultValue) : defaultValue;
    }

    public void setPropertyInt(String variable, int value) {
        this.properties.set(variable, value);
        this.properties.save();
    }

    public boolean getPropertyBoolean(String variable) {
        return this.getPropertyBoolean(variable, null);
    }

    public boolean getPropertyBoolean(String variable, Object defaultValue) {
        Object value = this.properties.exists(variable) ? this.properties.get(variable) : defaultValue;
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        switch (String.valueOf(value)) {
            case "on":
            case "true":
            case "1":
            case "yes":
                return true;
        }
        return false;
    }

    public void setPropertyBoolean(String variable, boolean value) {
        this.properties.set(variable, value ? "1" : "0");
        this.properties.save();
    }

    public PluginIdentifiableCommand getPluginCommand(String name) {
        Command command = this.commandMap.getCommand(name);
        if (command instanceof PluginIdentifiableCommand) {
            return (PluginIdentifiableCommand) command;
        } else {
            return null;
        }
    }

    public SynapseInterface getSynapseInterface() {
        return synapseInterface;
    }

    public Synapse getSynapse() {
        return synapse;
    }

    @Deprecated
    public void batchPackets(Player[] players, DataPacket[] packets) {
        this.batchPackets(players, packets, false);
    }

    @Deprecated
    public void batchPackets(Player[] players, DataPacket[] packets, boolean forceSync) {
        if (players == null || packets == null || players.length == 0 || packets.length == 0) {
            return;
        }

        byte[][] payload = new byte[packets.length * 2][];
        for (int i = 0; i < packets.length; i++) {
            DataPacket p = packets[i];
            int idx = i * 2;
            p.tryEncode(players[0].getProtocol());
            byte[] buf = p.getBuffer();
            payload[idx] = Binary.writeUnsignedVarInt(buf.length);
            payload[idx + 1] = buf;
        }
        byte[] data;
        data = Binary.appendBytes(payload);

        List<InetSocketAddress> targets = new ObjectArrayList<>();
        for (Player p : players) {
            if (!p.closed) {
                targets.add(p.getSocketAddress());
            }
        }

        Compressor compressor = Compressor.byProtocol(players[0].getProtocol());
        try {
            this.broadcastPacketsCallback(compressor.compress(data, networkCompressionLevel), targets, compressor);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void broadcastPacketsCallback(byte[] data, List<InetSocketAddress> targets, Compressor compressor) {
        BatchPacket pk = new BatchPacket();
        pk.compressor = compressor.getAlgorithm();
        pk.payload = data;

        for (InetSocketAddress i : targets) {
            Player player = this.players.get(i);
            if (player != null) {
                player.sendDataPacket(pk);
            }
        }
    }

    public boolean isPrimaryThread() {
        return Thread.currentThread() == currentThread;
    }

    public Thread getPrimaryThread() {
        return currentThread;
    }

    public static void addShutdownListener(Runnable listener) {
        Objects.requireNonNull(listener, "listener");
        SHUTDOWN_LISTENERS.add(listener);
    }

    private class ConsoleThread extends Thread implements InterruptibleThread {
        ConsoleThread() {
            super("Console");
            setDaemon(true);
        }

        @Override
        public void run() {
            console.start();
        }
    }
}
