package org.itxtech.nemisys.utils;

import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class ZlibSingleThreadLowMem implements ZlibProvider {
    private static final int BUFFER_SIZE = 8192;
    private static final Deflater DEFLATER = new Deflater(Deflater.BEST_COMPRESSION);
    private static final Inflater INFLATER = new Inflater();
    private static final byte[] BUFFER = new byte[BUFFER_SIZE];

    @Override
    public synchronized byte[] deflate(byte[][] datas, int level) throws IOException {
        DEFLATER.reset();
        FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
        bos.reset();
        for (byte[] data : datas) {
            DEFLATER.setInput(data);
            while (!DEFLATER.needsInput()) {
                int i = DEFLATER.deflate(BUFFER);
                bos.write(BUFFER, 0, i);
            }
        }
        DEFLATER.finish();
        while (!DEFLATER.finished()) {
            int i = DEFLATER.deflate(BUFFER);
            bos.write(BUFFER, 0, i);
        }
        //Deflater::end is called the time when the process exits.
        return bos.toByteArray();
    }

    @Override
    public synchronized byte[] deflate(byte[] data, int level) throws IOException {
        DEFLATER.reset();
        DEFLATER.setInput(data);
        DEFLATER.finish();
        FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
        bos.reset();
        try {
            while (!DEFLATER.finished()) {
                int i = DEFLATER.deflate(BUFFER);
                bos.write(BUFFER, 0, i);
            }
        } finally {
            //deflater.end();
        }
        return bos.toByteArray();
    }

    @Override
    public synchronized byte[] inflate(byte[] data, int maxSize) throws IOException {
        if (data.length == 0) {
            throw new DataLengthException("no data");
        }
        if (maxSize > 0 && data.length >= maxSize) {
            throw new DataLengthException("Input data exceeds maximum size");
        }
        INFLATER.reset();
        INFLATER.setInput(data);
        INFLATER.finished();
        FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
        bos.reset();
        try {
            int length = 0;
            while (!INFLATER.finished()) {
                int i = INFLATER.inflate(BUFFER);
                if (i == 0) {
                    throw new IOException("Could not decompress the data. Needs input: " + INFLATER.needsInput() + ", Needs Dictionary: " + INFLATER.needsDictionary());
                }
                length += i;
                if (maxSize > 0 && length >= maxSize) {
                    throw new DataLengthException("Inflated data exceeds maximum size");
                }
                bos.write(BUFFER, 0, i);
            }
            return bos.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException("Unable to inflate zlib stream", e);
        }
    }
}
