package org.itxtech.nemisys.event.server;

import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.event.HandlerList;
import org.itxtech.nemisys.plugin.Plugin;
import org.itxtech.nemisys.plugin.PluginDescription;
import org.itxtech.nemisys.utils.Binary;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class QueryRegenerateEvent extends ServerEvent {

    private static final HandlerList handlers = new HandlerList();
    private static final String GAME_ID = "MINECRAFTPE";
    private int timeout;
    private String serverName;
    private boolean listPlugins;
    private Plugin[] plugins;
    private Player[] players;
    private final String gameType;
    private final String version;
    private final String serverEngine;
    private String map;
    private int numPlayers;
    private int maxPlayers;
    private final String whitelist;
    private final int port;
    private final String ip;
    private Map<String, String> extraData = new Object2ObjectOpenHashMap<>();

    public QueryRegenerateEvent(Server server) {
        this(server, 5);
    }

    public QueryRegenerateEvent(Server server, int timeout) {
        this.timeout = timeout;
        this.serverName = server.getMotd();
//        this.listPlugins = (boolean) server.getConfig("settings.query-plugins", false);
//        this.plugins = server.getPluginManager().getPlugins().values().toArray(new Plugin[0]);
        this.plugins = new Plugin[0];
//        this.players = server.getOnlinePlayers().values().toArray(new Player[0]);
        this.players = new Player[0];

        this.gameType = "SMP";
        this.version = server.getVersion();
        this.serverEngine = server.getName() + " " + server.getNemisysVersion();
        this.map = "Nemisys";
        this.numPlayers = server.getOnlinePlayers().size();
        if (server.getConfiguration().isPlusOneMaxCount()) {
            this.maxPlayers = this.numPlayers + 1;
        } else {
            this.maxPlayers = server.getMaxPlayers();
        }
        this.whitelist = "off";
        this.ip = server.getIp();
        this.port = server.getPort();
    }

    public static HandlerList getHandlers() {
        return handlers;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String getServerName() {
        return serverName;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public boolean canListPlugins() {
        return this.listPlugins;
    }

    public void setListPlugins(boolean listPlugins) {
        this.listPlugins = listPlugins;
    }

    public Plugin[] getPlugins() {
        return plugins;
    }

    public void setPlugins(Plugin[] plugins) {
        this.plugins = plugins;
    }

    public Player[] getPlayerList() {
        return players;
    }

    public void setPlayerList(Player[] players) {
        this.players = players;
    }

    public int getPlayerCount() {
        return this.numPlayers;
    }

    public void setPlayerCount(int count) {
        this.numPlayers = count;
    }

    public int getMaxPlayerCount() {
        return this.maxPlayers;
    }

    public void setMaxPlayerCount(int count) {
        this.maxPlayers = count;
    }

    public String getWorld() {
        return map;
    }

    public void setWorld(String world) {
        this.map = world;
    }

    public Map<String, String> getExtraData() {
        return extraData;
    }

    public void setExtraData(Map<String, String> extraData) {
        this.extraData = extraData;
    }

    public byte[] getLongQuery() {
        ByteBuffer query = ByteBuffer.allocate(65536);
        StringBuilder plist = new StringBuilder(this.serverEngine);
        if (this.plugins.length > 0 && this.listPlugins) {
            plist.append(":");
            for (Plugin p : this.plugins) {
                PluginDescription d = p.getDescription();
                plist.append(" ").append(d.getName().replace(";", "").replace(":", "").replace(" ", "_")).append(" ").append(d.getVersion().replace(";", "").replace(":", "").replace(" ", "_")).append(";");
            }
            plist = new StringBuilder(plist.substring(0, plist.length() - 2));
        }

        query.put("splitnum".getBytes());
        query.put((byte) 0x00);
        query.put((byte) 128);
        query.put((byte) 0x00);

        LinkedHashMap<String, String> KVdata = new LinkedHashMap<>();
        KVdata.put("hostname", this.serverName);
        KVdata.put("gametype", this.gameType);
        KVdata.put("game_id", GAME_ID);
        KVdata.put("version", this.version);
        KVdata.put("server_engine", this.serverEngine);
        KVdata.put("plugins", plist.toString());
        KVdata.put("map", this.map);
        KVdata.put("numplayers", String.valueOf(this.numPlayers));
        KVdata.put("maxplayers", String.valueOf(this.maxPlayers));
        KVdata.put("whitelist", this.whitelist);
        KVdata.put("hostip", this.ip);
        KVdata.put("hostport", String.valueOf(this.port));

        for (Map.Entry<String, String> entry : KVdata.entrySet()) {
            query.put(entry.getKey().getBytes(StandardCharsets.UTF_8));
            query.put((byte) 0x00);
            query.put(entry.getValue().getBytes(StandardCharsets.UTF_8));
            query.put((byte) 0x00);
        }

        query.put(new byte[]{0x00, 0x01}).put("player_".getBytes()).put(new byte[]{0x00, 0x00});

        for (Player player : this.players) {
            if (player.getName() != null) {
                query.put(player.getName().getBytes(StandardCharsets.UTF_8));
                query.put((byte) 0x00);
            }
        }

        query.put((byte) 0x00);
        return Arrays.copyOf(query.array(), query.position());
    }

    public byte[] getShortQuery() {
        ByteBuffer query = ByteBuffer.allocate(65536);
        query.put(this.serverName.getBytes(StandardCharsets.UTF_8));
        query.put((byte) 0x00);
        query.put(this.gameType.getBytes(StandardCharsets.UTF_8));
        query.put((byte) 0x00);
        query.put(this.map.getBytes(StandardCharsets.UTF_8));
        query.put((byte) 0x00);
        query.put(String.valueOf(this.numPlayers).getBytes(StandardCharsets.UTF_8));
        query.put((byte) 0x00);
        query.put(String.valueOf(this.maxPlayers).getBytes(StandardCharsets.UTF_8));
        query.put((byte) 0x00);
        query.put(Binary.writeLShort(this.port));
        query.put(this.ip.getBytes(StandardCharsets.UTF_8));
        query.put((byte) 0x00);
        return Arrays.copyOf(query.array(), query.position());
    }

}
