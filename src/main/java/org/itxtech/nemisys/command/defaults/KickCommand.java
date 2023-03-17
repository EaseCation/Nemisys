package org.itxtech.nemisys.command.defaults;

import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.command.CommandSender;
import org.itxtech.nemisys.event.TranslationContainer;
import org.itxtech.nemisys.utils.TextFormat;

/**
 * Created on 2015/11/11 by xtypr.
 * Package org.itxtech.nemisys.command.defaults in project Nukkit .
 */
public class KickCommand extends VanillaCommand {

    public KickCommand(String name) {
        super(name, "%nemisys.command.kick.description", "%commands.kick.usage");
    }

    @Override
    public boolean execute(CommandSender sender, String commandLabel, String[] args) {
        if (args.length == 0) {
            sender.sendMessage(new TranslationContainer("commands.generic.usage", this.usageMessage));
            return false;
        }

        String name = args[0];

        StringBuilder reason = new StringBuilder("Kicked by admin");
        for (int i = 1; i < args.length; i++) {
            reason.append(args[i]).append(" ");
        }

        if (reason.toString().endsWith(" ")) {
            reason = new StringBuilder(reason.substring(0, reason.length() - 1));
        }

        Player player = sender.getServer().getPlayerExact(name);
        if (player != null) {
            player.close(reason.toString());
            if (reason.length() >= 1) {
                sender.sendMessage(new TranslationContainer("commands.kick.success.reason", new String[]{player.getName(), reason.toString()}));
            } else {
                sender.sendMessage(new TranslationContainer("commands.kick.success", player.getName()));
            }
        } else {
            sender.sendMessage(new TranslationContainer(TextFormat.RED + "%commands.generic.player.notFound"));
        }

        return true;
    }
}
