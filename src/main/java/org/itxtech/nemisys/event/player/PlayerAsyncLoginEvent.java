package org.itxtech.nemisys.event.player;

import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.event.AsyncEvent;
import org.itxtech.nemisys.event.HandlerList;

/**
 * This event is called asynchronously
 *
 * @author CreeperFace
 */
public class PlayerAsyncLoginEvent extends PlayerEvent implements AsyncEvent {

    private static final HandlerList handlers = new HandlerList();

    public static HandlerList getHandlers() {
        return handlers;
    }

    private LoginResult loginResult = LoginResult.SUCCESS;
    private String kickMessage = "Plugin Reason";
    private String transferClientHash;

    public PlayerAsyncLoginEvent(Player player, String transferClientHash) {
        super(player);
        this.transferClientHash = transferClientHash;
    }

    public LoginResult getLoginResult() {
        return loginResult;
    }

    public void setLoginResult(LoginResult loginResult) {
        this.loginResult = loginResult;
    }

    public String getKickMessage() {
        return kickMessage;
    }

    public void setKickMessage(String kickMessage) {
        this.kickMessage = kickMessage;
    }

    public void setTransferClientHash(String transferClientHash) {
        this.transferClientHash = transferClientHash;
    }

    public String getTransferClientHash() {
        return transferClientHash;
    }

    public void allow(String clientHash) {
        this.loginResult = LoginResult.SUCCESS;
        this.transferClientHash = clientHash;
    }

    public void disAllow(String message) {
        this.loginResult = LoginResult.KICK;
        this.kickMessage = message;
    }

    public enum LoginResult {
        SUCCESS,
        KICK
    }
}
