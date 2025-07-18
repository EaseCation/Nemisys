package org.itxtech.nemisys.utils;

import io.netty.util.concurrent.FastThreadLocal;

import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class ZlibThreadLocal implements ZlibProvider {
    private static final FastThreadLocal<Inflater> INFLATER = new FastThreadLocal<>() {
        @Override
        protected Inflater initialValue() {
            return new Inflater();
        }
    };
    private static final FastThreadLocal<Deflater> DEFLATER = new FastThreadLocal<>() {
        @Override
        protected Deflater initialValue() {
            return new Deflater();
        }
    };
    private static final FastThreadLocal<byte[]> BUFFER = new FastThreadLocal<>() {
        @Override
        protected byte[] initialValue() {
            return new byte[8192];
        }
    };

    @Override
    public byte[] deflate(byte[][] datas, int level) throws IOException {
        Deflater deflater = DEFLATER.get();
        try {
            deflater.setLevel(level);
            FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
            bos.reset();
            byte[] buffer = BUFFER.get();

            for (byte[] data : datas) {
                deflater.setInput(data);
                while (!deflater.needsInput()) {
                    int i = deflater.deflate(buffer);
                    bos.write(buffer, 0, i);
                }
            }
            deflater.finish();
            while (!deflater.finished()) {
                int i = deflater.deflate(buffer);
                bos.write(buffer, 0, i);
            }
            return bos.toByteArray();
        } finally {
            deflater.reset();
        }
    }

    @Override
    public byte[] deflate(byte[] data, int level) throws IOException {
        Deflater deflater = DEFLATER.get();
        try {
            deflater.setLevel(level);
            deflater.setInput(data);
            deflater.finish();
            FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
            bos.reset();
            byte[] buffer = BUFFER.get();
            while (!deflater.finished()) {
                int i = deflater.deflate(buffer);
                bos.write(buffer, 0, i);
            }
            return bos.toByteArray();
        } finally {
            deflater.reset();
        }
    }

    @Override
    public byte[] inflate(byte[] data, int maxSize) throws IOException {
        if (data.length == 0) {
            throw new DataLengthException("no data");
        }
        if (maxSize > 0 && data.length >= maxSize) {
            throw new DataLengthException("Input data exceeds maximum size");
        }
        Inflater inflater = INFLATER.get();
        try {
            inflater.setInput(data);
            inflater.finished();
            FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
            bos.reset();

            byte[] buffer = BUFFER.get();
            try {
                int length = 0;
                while (!inflater.finished()) {
                    int i = inflater.inflate(buffer);
                    if (i == 0) {
                        throw new IOException("Could not decompress the data. Needs input: " + inflater.needsInput() + ", Needs Dictionary: " + inflater.needsDictionary());
                    }
                    length += i;
                    if (maxSize > 0 && length >= maxSize) {
                        throw new DataLengthException("Inflated data exceeds maximum size");
                    }
                    bos.write(buffer, 0, i);
                }
                return bos.toByteArray();
            } catch (DataFormatException e) {
                throw new IOException("Unable to inflate zlib stream", e);
            }
        } finally {
            inflater.reset();
        }
    }
}
