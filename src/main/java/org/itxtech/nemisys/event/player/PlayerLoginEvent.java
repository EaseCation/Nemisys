package org.itxtech.nemisys.event.player;

import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.event.Cancellable;
import org.itxtech.nemisys.event.HandlerList;

public class PlayerLoginEvent extends PlayerEvent implements Cancellable {
    private static final HandlerList handlers = new HandlerList();
    protected String kickMessage;
    public PlayerLoginEvent(Player player, String kickMessage) {
        super(player);
        this.kickMessage = kickMessage;
    }

    public static HandlerList getHandlers() {
        return handlers;
    }

    public String getKickMessage() {
        return kickMessage;
    }

    public void setKickMessage(String kickMessage) {
        this.kickMessage = kickMessage;
    }

    @Override
    public void setCancelled(boolean value) {
        super.setCancelled(value);
    }
}
