package org.itxtech.nemisys.event.plugin;

import org.itxtech.nemisys.event.HandlerList;
import org.itxtech.nemisys.plugin.Plugin;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class PluginDisableEvent extends PluginEvent {

    private static final HandlerList handlers = new HandlerList();

    public PluginDisableEvent(Plugin plugin) {
        super(plugin);
    }

    public static HandlerList getHandlers() {
        return handlers;
    }
}
