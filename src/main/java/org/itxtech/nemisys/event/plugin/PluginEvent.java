package org.itxtech.nemisys.event.plugin;

import org.itxtech.nemisys.event.Event;
import org.itxtech.nemisys.plugin.Plugin;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public abstract class PluginEvent extends Event {

    private final Plugin plugin;

    public PluginEvent(Plugin plugin) {
        this.plugin = plugin;
    }

    public Plugin getPlugin() {
        return plugin;
    }
}
