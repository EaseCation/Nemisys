package org.itxtech.nemisys.utils;

import com.sun.management.OperatingSystemMXBean;
import com.sun.management.UnixOperatingSystemMXBean;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.LogManager;
import org.itxtech.nemisys.Nemisys;
import org.itxtech.nemisys.Server;

import java.lang.management.ManagementFactory;
import java.lang.management.MonitorInfo;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadInfo;
import java.util.concurrent.TimeUnit;

@Log4j2
public class Watchdog extends Thread {

    private final Server server;
    private final long time;
    public boolean running;
    private boolean responding = true;

    public Watchdog(Server server, long time) {
        super("Watchdog");
        setDaemon(true);
        this.server = server;
        this.time = time;
        this.running = true;
    }

    public void kill() {
        running = false;
        synchronized (this) {
            this.notifyAll();
        }
    }

    @Override
    public void run() {
        while (this.running) {
            long current = server.getNextTick();
            if (current != 0) {
                long diff = System.currentTimeMillis() - current;
                if (!responding && diff > time * 2) {
                    log.fatal("Watchdog shutdown timeout!");
                    LogManager.shutdown();
                    System.exit(1); // Kill the server if it gets stuck on shutdown
                }
                if (server.isRunning() && diff > time) {
                    if (responding) {
                        log.fatal("--------- Server stopped responding --------- (" + Math.round(diff / 1000d) + "s)");

                        log.fatal("---------------- Main thread ----------------");
                        dumpThread(ManagementFactory.getThreadMXBean().getThreadInfo(this.server.getPrimaryThread().getId(), Integer.MAX_VALUE));

                        log.fatal("---------------- All threads ----------------");
                        ThreadInfo[] threads = ManagementFactory.getThreadMXBean().dumpAllThreads(true, true);
                        for (int i = 0; i < threads.length; i++) {
                            if (i != 0) log.fatal("------------------------------");
                            dumpThread(threads[i]);
                        }

                        log.fatal("------------------- System -------------------");
                        log.fatal("Nukkit Uptime: " + formatUptime(System.currentTimeMillis() - Nemisys.START_TIME));
                        Runtime runtime = Runtime.getRuntime();
                        log.fatal("Available Processors: " + runtime.availableProcessors());
                        log.fatal("Free VM Memory: " + runtime.freeMemory() + " (" + runtime.totalMemory() + " | " + runtime.maxMemory() + ")");
                        RuntimeMXBean rt =  ManagementFactory.getRuntimeMXBean();
                        if (rt != null) {
                            log.fatal("Java Uptime: " + formatUptime(rt.getUptime()));
                            log.fatal("VM: " + rt.getVmName() + " (" + rt.getVmVersion() + ") " + rt.getVmVendor());
                        }
                        OperatingSystemMXBean os = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
                        if (os != null) {
                            log.fatal("OS: " + os.getName() + " (" + os.getVersion() + ") " + os.getArch());
                            log.fatal("OS Average Load: " + os.getSystemLoadAverage());
                            log.fatal("OS Load: " + os.getSystemCpuLoad());
                            log.fatal("VM Load: " + os.getProcessCpuLoad());
                            log.fatal("Free Physical Memory: " + os.getFreePhysicalMemorySize() + " (" + os.getTotalPhysicalMemorySize() + ")");
                            log.fatal("Free Swap Memory: " + os.getFreeSwapSpaceSize() + " (" + os.getTotalSwapSpaceSize() + ")");
                            if (os instanceof UnixOperatingSystemMXBean) {
                                UnixOperatingSystemMXBean unix = (UnixOperatingSystemMXBean) os;
                                log.fatal("Open File Descriptors: " + unix.getOpenFileDescriptorCount() + " (" + unix.getMaxFileDescriptorCount() + ")");
                            }
                        }
                        log.fatal("Tick: " + server.getTick());

                        log.fatal("---------------------------------------------");
                        responding = false;
                        new Thread(this.server::forceShutdown, "Watchdog Killer").start();
                    }
                } else {
                    responding = true;
                }
            }
            try {
                synchronized (this) {
                    this.wait(Math.max(time / 4, 1000));
                }
            } catch (InterruptedException ignore) {
            }
        }
    }

    private static void dumpThread(ThreadInfo thread) {
        log.fatal("Current Thread: " + thread.getThreadName());
        log.fatal("\tPID: " + thread.getThreadId() + " | Suspended: " + thread.isSuspended() + " | Native: " + thread.isInNative() + " | State: " + thread.getThreadState());
        // Monitors
        if (thread.getLockedMonitors().length != 0) {
            log.fatal("\tThread is waiting on monitor(s):");
            for (MonitorInfo monitor : thread.getLockedMonitors()) {
                log.fatal("\t\tLocked on:" + monitor.getLockedStackFrame());
            }
        }

        log.fatal("\tStack:");
        for (StackTraceElement stack : thread.getStackTrace()) {
            log.fatal("\t\t" + stack);
        }
    }

    private static String formatUptime(long uptime) {
        long days = TimeUnit.MILLISECONDS.toDays(uptime);
        uptime -= TimeUnit.DAYS.toMillis(days);
        long hours = TimeUnit.MILLISECONDS.toHours(uptime);
        uptime -= TimeUnit.HOURS.toMillis(hours);
        long minutes = TimeUnit.MILLISECONDS.toMinutes(uptime);
        uptime -= TimeUnit.MINUTES.toMillis(minutes);
        long seconds = TimeUnit.MILLISECONDS.toSeconds(uptime);
        return days + " days " + hours + " hours " + minutes + " minutes " + seconds + " seconds";
    }
}
