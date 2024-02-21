package org.itxtech.nemisys.utils;

public class StacklessException extends Exception {
    public StacklessException() {
        super(null, null, true, false);
    }

    public StacklessException(String message) {
        super(message, null, true, false);
    }

    public StacklessException(String message, Throwable cause) {
        super(message, cause, true, false);
    }

    public StacklessException(Throwable cause) {
        super(null, cause, true, false);
    }

    protected StacklessException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    @Override
    public Throwable fillInStackTrace() {
        return this;
    }
}
