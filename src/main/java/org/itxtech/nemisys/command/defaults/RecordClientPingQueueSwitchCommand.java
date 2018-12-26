package org.itxtech.nemisys.command.defaults;

import org.itxtech.nemisys.command.CommandSender;
import org.itxtech.nemisys.event.TranslationContainer;
import org.itxtech.nemisys.network.protocol.mcpe.ProtocolInfo;
import org.itxtech.nemisys.plugin.Plugin;
import org.itxtech.nemisys.plugin.PluginDescription;
import org.itxtech.nemisys.raknet.server.Session;
import org.itxtech.nemisys.utils.TextFormat;

import java.util.List;

/**
 * Created on 2015/11/12 by xtypr.
 * Package org.itxtech.nemisys.command.defaults in project Nukkit .
 */
public class RecordClientPingQueueSwitchCommand extends VanillaCommand {

    public RecordClientPingQueueSwitchCommand(String name) {
        super(name,
                "RecordClientPingQueueSwitchCommand",
                "/recordpingqueue <on|off>"
        );
    }

    @Override
    public boolean execute(CommandSender sender, String commandLabel, String[] args) {
        if (args.length > 0) {
            switch (args[0]) {
                case "on":
                    Session.recordClientPingQueue = true;
                    sender.sendMessage("Turned on Record Client Ping Queue");
                    break;
                case "off":
                    Session.recordClientPingQueue = false;
                    sender.sendMessage("Turned off Record Client Ping Queue");
                    break;
                default:
                    sender.sendMessage(this.getUsage());
                    break;
            }
        }
        return true;
    }
}
