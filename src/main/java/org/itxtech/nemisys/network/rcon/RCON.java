package org.itxtech.nemisys.network.rcon;

import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.command.RemoteConsoleCommandSender;
import org.itxtech.nemisys.event.server.RemoteServerCommandEvent;
import org.itxtech.nemisys.utils.TextFormat;

import java.io.IOException;

/**
 * Implementation of Source RCON protocol.
 * https://developer.valvesoftware.com/wiki/Source_RCON_Protocol
 * <p>
 * Wrapper for RCONServer. Handles data.
 *
 * @author Tee7even
 */
public class RCON {
    private final Server server;
    private RCONServer serverThread;

    public RCON(Server server, String password, String address, int port) {
        this.server = server;

        if (password.isEmpty()) {
            server.getLogger().critical("Failed to start RCON: password is empty");
            return;
        }

        try {
            this.serverThread = new RCONServer(address, port, password);
            this.serverThread.start();
        } catch (IOException e) {
            this.server.getLogger().critical("Failed to start RCON: ", e);
            return;
        }

        this.server.getLogger().info("RCON is running on " + address + ":" + port);
    }

    public void check() {
        if (this.serverThread == null) {
            return;
        } else if (!this.serverThread.isAlive()) {
            return;
        }

        RCONCommand command;
        while ((command = serverThread.receive()) != null) {
            RemoteConsoleCommandSender sender = new RemoteConsoleCommandSender();
            RemoteServerCommandEvent event = new RemoteServerCommandEvent(sender, command.getCommand());
            this.server.getPluginManager().callEvent(event);

            if (!event.isCancelled()) {
                this.server.dispatchCommand(sender, command.getCommand());
            }

            this.serverThread.respond(command.getSender(), command.getId(), TextFormat.clean(sender.getMessages()));
        }
    }

    public void close() {
        try {
            synchronized (serverThread) {
                serverThread.close();
                serverThread.wait(5000);
            }
        } catch (InterruptedException exception) {
            //
        }
    }
}
