package org.itxtech.nemisys.event.player;

import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.event.HandlerList;
import org.itxtech.nemisys.utils.LoginChainData;

/**
 * Fired before Xbox authentication check during login.
 * Plugins can override the authentication result (e.g., for ViaProxy auth bridge).
 * If setAuthenticated(true), Xbox auth check is skipped.
 */
public class PlayerPreAuthEvent extends PlayerEvent {
    private static final HandlerList handlers = new HandlerList();
    private final LoginChainData loginChainData;
    private boolean authenticated;
    private String kickMessage;

    public PlayerPreAuthEvent(Player player, LoginChainData loginChainData, boolean authenticated) {
        super(player);
        this.loginChainData = loginChainData;
        this.authenticated = authenticated;
    }

    public LoginChainData getLoginChainData() {
        return loginChainData;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    public String getKickMessage() {
        return kickMessage;
    }

    public void setKickMessage(String kickMessage) {
        this.kickMessage = kickMessage;
    }

    public static HandlerList getHandlers() {
        return handlers;
    }
}
