package org.itxtech.nemisys.utils.bugreport;

import lombok.extern.log4j.Log4j2;

import java.lang.Thread.UncaughtExceptionHandler;

@Log4j2
public class ExceptionHandler implements UncaughtExceptionHandler {

    public static void registerExceptionHandler() {
        Thread.setDefaultUncaughtExceptionHandler(new ExceptionHandler());
    }

    @Override
    public void uncaughtException(Thread thread, Throwable throwable) {
        handle(thread, throwable);
    }

    public void handle(Thread thread, Throwable throwable) {
        log.throwing(throwable);

        try {
            new BugReportGenerator(throwable).start();
        } catch (Exception exception) {
            // Fail Safe
        }
    }

}
