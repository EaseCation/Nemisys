package org.itxtech.nemisys.synapse;

import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.network.RakNettyInterface;
import org.itxtech.nemisys.network.SourceInterface;
import org.itxtech.nemisys.network.protocol.mcpe.DataPacket;
import org.itxtech.nemisys.utils.Config;
import org.itxtech.nemisys.utils.ConfigSection;
import org.itxtech.nemisys.utils.MainLogger;

import java.io.File;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Synapse
 * ===============
 * author: boybook
 * EaseCation Network Project
 * nemisys
 * ===============
 */
public class Synapse {

    private Server server;
    private Config config;

    private Map<String, SynapseEntry> synapseEntries = new HashMap<>();

    public Synapse(Server server) {
        this.server = server;
        this.server.getLogger().notice("Enabling Synapse Client...");
        this.config = new Config(new File(server.getFilePath() + "/synapse.yml"), Config.YAML);

        List entries = this.config.getList("entries");
        for (Object entry : entries) {
            @SuppressWarnings("unchecked")
            ConfigSection section = new ConfigSection((LinkedHashMap) entry);
            String serverIp = section.getString("server-ip", "127.0.0.1");
            int port = section.getInt("server-port", 10305);
            boolean isMainServer = section.getBoolean("isMainServer");
            String password = section.getString("password");
            String serverDescription = section.getString("description");
            if (!serverIp.equals("0")) {
                SynapseEntry synapseEntry = new SynapseEntry(this, serverIp, port, isMainServer, password, serverDescription);
                this.addSynapseEntry(synapseEntry);
            }
        }

        for (SourceInterface interfaz : this.getServer().getNetwork().getInterfaces()) {
            if (interfaz instanceof RakNettyInterface) {
                if (this.getConfig().getBoolean("disable-rak")) {
                    interfaz.shutdown();
                    break;
                }
            }
        }

        this.server.getLogger().notice("Enabled Synapse Client");
    }

    public Config getConfig() {
        return config;
    }

    public Server getServer() {
        return server;
    }

    public MainLogger getLogger() {
        return this.server.getLogger();
    }

    public Map<String, SynapseEntry> getSynapseEntries() {
        return synapseEntries;
    }

    public void addSynapseEntry(SynapseEntry entry) {
        this.synapseEntries.put(entry.getHash(), entry);
    }

    public SynapseEntry getSynapseEntry(String hash) {
        return this.synapseEntries.get(hash);
    }

    public DataPacket getPacket(byte[] buffer) {
        DataPacket packet;
        if ((packet = this.getServer().getNetwork().getPacket(buffer[0])) != null) {
                    /*System.out.println("first bits: "+buf[1]+"   "+buf[2]);
                    System.out.println("other bits: "+ Arrays.toString(buf));*/
            packet.setBuffer(buffer, 3);

            try {
                packet.decode();
            } catch (Exception e) { //probably 1.1 client ?
                //e.printStackTrace();
                try {
                    packet.setBuffer(buffer, 1); //skip 2 more bytes
                    packet.decode();
                } catch (Exception e1) {
                    return null;
                }
            }
            return packet;
        }
        return null;
    }

}
