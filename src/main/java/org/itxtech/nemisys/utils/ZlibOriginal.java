package org.itxtech.nemisys.utils;

import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class ZlibOriginal implements ZlibProvider {

    @Override
    public byte[] deflate(byte[][] datas, int level) throws IOException {
        Deflater deflater = new Deflater(level);
        byte[] buffer = new byte[1024];
        FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
        bos.reset();
        try {
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
        } finally {
            deflater.end();
        }
        return bos.toByteArray();
    }

    @Override
    public byte[] deflate(byte[] data, int level) throws IOException {
        Deflater deflater = new Deflater(level);
        deflater.setInput(data);
        deflater.finish();
        FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
        bos.reset();
        byte[] buf = new byte[1024];
        try {
            while (!deflater.finished()) {
                int i = deflater.deflate(buf);
                bos.write(buf, 0, i);
            }
        } finally {
            deflater.end();
        }
        return bos.toByteArray();
    }

    @Override
    public byte[] inflate(byte[] data, int maxSize) throws IOException {
        if (data.length == 0) {
            throw new DataLengthException("no data");
        }
        if (maxSize > 0 && data.length >= maxSize) {
            throw new DataLengthException("Input data exceeds maximum size");
        }
        Inflater inflater = new Inflater();
        inflater.setInput(data);
        inflater.finished();
        FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
        bos.reset();

        byte[] buffer = new byte[1024];
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
    }
}
