package org.itxtech.nemisys.utils;

public class StacklessRuntimeException extends RuntimeException {
    public StacklessRuntimeException() {
        super(null, null, true, false);
    }

    public StacklessRuntimeException(String message) {
        super(message, null, true, false);
    }

    public StacklessRuntimeException(String message, Throwable cause) {
        super(message, cause, true, false);
    }

    public StacklessRuntimeException(Throwable cause) {
        super(null, cause, true, false);
    }

    protected StacklessRuntimeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    @Override
    public Throwable fillInStackTrace() {
        return this;
    }
}
