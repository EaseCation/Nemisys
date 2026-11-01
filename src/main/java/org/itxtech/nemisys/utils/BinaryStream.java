package org.itxtech.nemisys.utils;

import it.unimi.dsi.fastutil.booleans.BooleanArrayList;
import it.unimi.dsi.fastutil.booleans.BooleanCollection;
import it.unimi.dsi.fastutil.bytes.ByteArrayList;
import it.unimi.dsi.fastutil.bytes.ByteCollection;
import it.unimi.dsi.fastutil.chars.CharArrayList;
import it.unimi.dsi.fastutil.chars.CharCollection;
import it.unimi.dsi.fastutil.doubles.DoubleArrayList;
import it.unimi.dsi.fastutil.doubles.DoubleCollection;
import it.unimi.dsi.fastutil.floats.FloatArrayList;
import it.unimi.dsi.fastutil.floats.FloatCollection;
import it.unimi.dsi.fastutil.ints.IntArrayList;
import it.unimi.dsi.fastutil.ints.IntCollection;
import it.unimi.dsi.fastutil.longs.LongArrayList;
import it.unimi.dsi.fastutil.longs.LongCollection;
import it.unimi.dsi.fastutil.objects.*;
import it.unimi.dsi.fastutil.shorts.ShortArrayList;
import it.unimi.dsi.fastutil.shorts.ShortCollection;

import javax.annotation.Nullable;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.*;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class BinaryStream {

    public int offset;
    private byte[] buffer;
    private int count;

    private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

    public BinaryStream() {
        this.buffer = new byte[32];
        this.offset = 0;
        this.count = 0;
    }

    public BinaryStream(int initialCapacity) {
        this.buffer = new byte[initialCapacity];
        this.offset = 0;
        this.count = 0;
    }

    public BinaryStream(byte[] buffer) {
        this(buffer, 0);
    }

    public BinaryStream(byte[] buffer, int offset) {
        this.buffer = buffer;
        this.offset = offset;
        this.count = buffer.length;
    }

    public void reuse() {
        this.offset = 0;
        this.count = 0;
    }

    public void reset() {
        this.buffer = new byte[32];
        this.offset = 0;
        this.count = 0;
    }

    public final void superReset() {
        this.buffer = new byte[32];
        this.offset = 0;
        this.count = 0;
    }

    public void setBuffer(byte[] buffer) {
        this.buffer = buffer;
        this.count = buffer == null ? -1 : buffer.length;
    }

    public void setBuffer(byte[] buffer, int offset) {
        this.setBuffer(buffer);
        this.setOffset(offset);
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public byte[] getBuffer() {
        return Arrays.copyOf(buffer, count);
    }

    public byte[] getBuffer(int from) {
        return Arrays.copyOfRange(buffer, from, count);
    }

    public byte[] getBuffer(int from, int to) {
        return Arrays.copyOfRange(buffer, from, to);
    }

    public byte[] getBufferUnsafe() {
        return buffer;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public byte[] get() {
        return this.get(this.count - this.offset);
    }

    public byte[] get(int len) {
        if (len < 0) {
            this.offset = this.count - 1;
            return new byte[0];
        }
        len = Math.min(len, this.count - this.offset);
        this.offset += len;
        return Arrays.copyOfRange(this.buffer, this.offset - len, this.offset);
    }

    public void skip(int len) {
        if (len <= 0) {
            return;
        }
        this.offset += Math.min(len, this.count - this.offset);
    }

    public void put(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return;
        }

        this.ensureCapacity(this.count + bytes.length);

        System.arraycopy(bytes, 0, this.buffer, this.count, bytes.length);
        this.count += bytes.length;
    }

    public void put(byte[] bytes, int length) {
        if (bytes == null) {
            return;
        }
        length = Math.min(bytes.length, length);
        if (length <= 0) {
            return;
        }

        this.ensureCapacity(this.count + length);

        System.arraycopy(bytes, 0, this.buffer, this.count, length);
        this.count += length;
    }

    /**
     * 仅用于很小的空数组. 例如1个字节的空数组.
     */
    public void putEmptyBytes(int length) {
        if (length <= 0) {
            return;
        }
        int newLength = this.count + length;
        this.ensureCapacity(newLength);

        for (int i = this.count; i < newLength; i++) {
            this.buffer[i] = 0;
        }
        this.count = newLength;
    }

    private int prepareWriterIndex(int length) {
        this.ensureCapacity(this.count + length);
        int writerIndex = this.count;
        this.count += length;
        return writerIndex;
    }

    public long getLong() {
        return Binary.readLong(this.get(8));
    }

    public void putLong(long l) {
        int index = this.prepareWriterIndex(8);
        Binary.writeLong(l, this.buffer, index);
    }

    public int getInt() {
        return Binary.readInt(this.get(4));
    }

    public void putInt(int i) {
        int index = this.prepareWriterIndex(4);
        Binary.writeInt(i, this.buffer, index);
    }

    public long getLLong() {
        return Binary.readLLong(this.get(8));
    }

    public void putLLong(long l) {
        int index = this.prepareWriterIndex(8);
        Binary.writeLLong(l, this.buffer, index);
    }

    public int getLInt() {
        return Binary.readLInt(this.get(4));
    }

    public void putLInt(int i) {
        int index = this.prepareWriterIndex(4);
        Binary.writeLInt(i, this.buffer, index);
    }

    public int getShort() {
        return Binary.readShort(this.get(2));
    }

    public void putShort(int s) {
        int index = this.prepareWriterIndex(2);
        Binary.writeShort(s, this.buffer, index);
    }

    public int getLShort() {
        return Binary.readLShort(this.get(2));
    }

    public void putLShort(int s) {
        int index = this.prepareWriterIndex(2);
        Binary.writeLShort(s, this.buffer, index);
    }

    public float getFloat() {
        return Binary.readFloat(this.get(4));
    }

    public void putFloat(float v) {
        int index = this.prepareWriterIndex(4);
        Binary.writeFloat(v, this.buffer, index);
    }

    public float getLFloat() {
        return Binary.readLFloat(this.get(4));
    }

    public void putLFloat(float v) {
        int index = this.prepareWriterIndex(4);
        Binary.writeLFloat(v, this.buffer, index);
    }

    public double getDouble() {
        return Binary.readDouble(this.get(8));
    }

    public void putDouble(double v) {
        int index = this.prepareWriterIndex(8);
        Binary.writeDouble(v, this.buffer, index);
    }

    public double getLDouble() {
        return Binary.readLDouble(this.get(8));
    }

    public void putLDouble(double v) {
        int index = this.prepareWriterIndex(8);
        Binary.writeLDouble(v, this.buffer, index);
    }

    public int getTriad() {
        return Binary.readTriad(this.get(3));
    }

    public void putTriad(int triad) {
        int index = this.prepareWriterIndex(3);
        Binary.writeTriad(triad, this.buffer, index);
    }

    public int getLTriad() {
        return Binary.readLTriad(this.get(3));
    }

    public void putLTriad(int triad) {
        int index = this.prepareWriterIndex(3);
        Binary.writeLTriad(triad, this.buffer, index);
    }

    public boolean getBoolean() {
        return this.getByte() == 0x01;
    }

    public void putBoolean(boolean bool) {
        this.putByte((byte) (bool ? 1 : 0));
    }

    public byte getSingedByte() {
        return this.buffer[this.offset++];
    }

    public int getByte() {
        return this.buffer[this.offset++] & 0xff;
    }

    public void putByte(byte b) {
        this.ensureCapacity(this.count + 1);
        this.buffer[this.count++] = b;
    }

    public void putByte(int b) {
        putByte((byte) b);
    }

    public void putUUID(UUID uuid) {
        this.put(Binary.writeUUID(uuid));
    }

    public UUID getUUID() {
        return Binary.readUUID(this.get(16));
    }

    public byte[] getByteArray() {
        int len = (int) this.getUnsignedVarInt();
        if (!isReadable(len)) {
            throw new IndexOutOfBoundsException("array length mismatch");
        }
        return this.get(len);
    }

    public byte[] getByteArray(int maxLength) {
        int len = (int) this.getUnsignedVarInt();
        if (len > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + len + " > " + maxLength);
        }
        if (!isReadable(len)) {
            throw new IndexOutOfBoundsException("array length mismatch");
        }
        return this.get(len);
    }

    public void putByteArray(byte[] b) {
        this.putUnsignedVarInt(b.length);
        this.put(b);
    }

    public void putByteArray(byte[] b, int maxLength) {
        int len = b.length;
        if (len > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + len + " > " + maxLength);
        }
        this.putByteArray(b);
    }

    public String getString() {
        return new String(this.getByteArray(), StandardCharsets.UTF_8);
    }

    public String getString(int maxLength) {
        return new String(this.getByteArray(maxLength), StandardCharsets.UTF_8);
    }

    public void putString(String string) {
        byte[] b = string.getBytes(StandardCharsets.UTF_8);
        this.putByteArray(b);
    }

    public void putString(String string, int maxLength) {
        this.putByteArray(string.getBytes(StandardCharsets.UTF_8), maxLength);
    }

    public long getUnsignedVarInt() {
        return VarInt.readUnsignedVarInt(this);
    }

    public void putUnsignedVarInt(long v) {
        VarInt.writeUnsignedVarInt(this, v);
    }

    public int getVarInt() {
        return VarInt.readVarInt(this);
    }

    public void putVarInt(int v) {
        VarInt.writeVarInt(this, v);
    }

    public long getVarLong() {
        return VarInt.readVarLong(this);
    }

    public void putVarLong(long v) {
        VarInt.writeVarLong(this, v);
    }

    public long getUnsignedVarLong() {
        return VarInt.readUnsignedVarLong(this);
    }

    public void putUnsignedVarLong(long v) {
        VarInt.writeUnsignedVarLong(this, v);
    }

    /**
     * Reads and returns an EntityUniqueID
     *
     * @return int
     */
    public long getEntityUniqueId() {
        return this.getVarLong();
    }

    /**
     * Writes an EntityUniqueID
     */
    public void putEntityUniqueId(long eid) {
        this.putVarLong(eid);
    }

    /**
     * Reads and returns an EntityRuntimeID
     */
    public long getEntityRuntimeId() {
        return this.getUnsignedVarLong();
    }

    /**
     * Writes an EntityUniqueID
     */
    public void putEntityRuntimeId(long eid) {
        this.putUnsignedVarLong(eid);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public <T> T[] getArray(T[] array, Function<BinaryStream, T> function) {
        return getArray(array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public <T> T[] getArray(T[] array, Function<BinaryStream, T> function, int maxLength) {
        int count = (int) getUnsignedVarInt();
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public <T> T[] getArray(ToIntFunction<BinaryStream> lengthReader, T[] array, Function<BinaryStream, T> function) {
        return getArray(lengthReader, array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public <T> T[] getArray(ToIntFunction<BinaryStream> lengthReader, T[] array, Function<BinaryStream, T> function, int maxLength) {
        int count = lengthReader.applyAsInt(this);
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    public <T> T[] getArray(int length, T[] array, Function<BinaryStream, T> function) {
        Collection<T> collection = new ArrayList<>();
        for (int i = 0; i < length; i++) {
            collection.add(function.apply(this));
        }
        return collection.toArray(array);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public byte[] getArray(byte[] array, Object2ByteFunction<BinaryStream> function) {
        return getArray(array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public byte[] getArray(byte[] array, Object2ByteFunction<BinaryStream> function, int maxLength) {
        int count = (int) getUnsignedVarInt();
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public byte[] getArray(ToIntFunction<BinaryStream> lengthReader, byte[] array, Object2ByteFunction<BinaryStream> function) {
        return getArray(lengthReader, array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public byte[] getArray(ToIntFunction<BinaryStream> lengthReader, byte[] array, Object2ByteFunction<BinaryStream> function, int maxLength) {
        int count = lengthReader.applyAsInt(this);
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    public byte[] getArray(int length, byte[] array, Object2ByteFunction<BinaryStream> function) {
        ByteCollection collection = new ByteArrayList();
        for (int i = 0; i < length; i++) {
            collection.add(function.getByte(this));
        }
        return collection.toArray(array);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public short[] getArray(short[] array, Object2ShortFunction<BinaryStream> function) {
        return getArray(array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public short[] getArray(short[] array, Object2ShortFunction<BinaryStream> function, int maxLength) {
        int count = (int) getUnsignedVarInt();
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public short[] getArray(ToIntFunction<BinaryStream> lengthReader, short[] array, Object2ShortFunction<BinaryStream> function) {
        return getArray(lengthReader, array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public short[] getArray(ToIntFunction<BinaryStream> lengthReader, short[] array, Object2ShortFunction<BinaryStream> function, int maxLength) {
        int count = lengthReader.applyAsInt(this);
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    public short[] getArray(int length, short[] array, Object2ShortFunction<BinaryStream> function) {
        ShortCollection collection = new ShortArrayList();
        for (int i = 0; i < length; i++) {
            collection.add(function.getShort(this));
        }
        return collection.toArray(array);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public char[] getArray(char[] array, Object2CharFunction<BinaryStream> function) {
        return getArray(array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public char[] getArray(char[] array, Object2CharFunction<BinaryStream> function, int maxLength) {
        int count = (int) getUnsignedVarInt();
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public char[] getArray(ToIntFunction<BinaryStream> lengthReader, char[] array, Object2CharFunction<BinaryStream> function) {
        return getArray(lengthReader, array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public char[] getArray(ToIntFunction<BinaryStream> lengthReader, char[] array, Object2CharFunction<BinaryStream> function, int maxLength) {
        int count = lengthReader.applyAsInt(this);
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    public char[] getArray(int length, char[] array, Object2CharFunction<BinaryStream> function) {
        CharCollection collection = new CharArrayList();
        for (int i = 0; i < length; i++) {
            collection.add(function.getChar(this));
        }
        return collection.toArray(array);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public int[] getArray(int[] array, ToIntFunction<BinaryStream> function) {
        return getArray(array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public int[] getArray(int[] array, ToIntFunction<BinaryStream> function, int maxLength) {
        int count = (int) getUnsignedVarInt();
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public int[] getArray(ToIntFunction<BinaryStream> lengthReader, int[] array, ToIntFunction<BinaryStream> function) {
        return getArray(lengthReader, array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public int[] getArray(ToIntFunction<BinaryStream> lengthReader, int[] array, ToIntFunction<BinaryStream> function, int maxLength) {
        int count = lengthReader.applyAsInt(this);
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    public int[] getArray(int length, int[] array, ToIntFunction<BinaryStream> function) {
        IntCollection collection = new IntArrayList();
        for (int i = 0; i < length; i++) {
            collection.add(function.applyAsInt(this));
        }
        return collection.toArray(array);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public long[] getArray(long[] array, ToLongFunction<BinaryStream> function) {
        return getArray(array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public long[] getArray(long[] array, ToLongFunction<BinaryStream> function, int maxLength) {
        int count = (int) getUnsignedVarInt();
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public long[] getArray(ToIntFunction<BinaryStream> lengthReader, long[] array, ToLongFunction<BinaryStream> function) {
        return getArray(lengthReader, array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public long[] getArray(ToIntFunction<BinaryStream> lengthReader, long[] array, ToLongFunction<BinaryStream> function, int maxLength) {
        int count = lengthReader.applyAsInt(this);
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    public long[] getArray(int length, long[] array, ToLongFunction<BinaryStream> function) {
        LongCollection collection = new LongArrayList();
        for (int i = 0; i < length; i++) {
            collection.add(function.applyAsLong(this));
        }
        return collection.toArray(array);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public float[] getArray(float[] array, Object2FloatFunction<BinaryStream> function) {
        return getArray(array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public float[] getArray(float[] array, Object2FloatFunction<BinaryStream> function, int maxLength) {
        int count = (int) getUnsignedVarInt();
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public float[] getArray(ToIntFunction<BinaryStream> lengthReader, float[] array, Object2FloatFunction<BinaryStream> function) {
        return getArray(lengthReader, array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public float[] getArray(ToIntFunction<BinaryStream> lengthReader, float[] array, Object2FloatFunction<BinaryStream> function, int maxLength) {
        int count = lengthReader.applyAsInt(this);
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    public float[] getArray(int length, float[] array, Object2FloatFunction<BinaryStream> function) {
        FloatCollection collection = new FloatArrayList();
        for (int i = 0; i < length; i++) {
            collection.add(function.getFloat(this));
        }
        return collection.toArray(array);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public double[] getArray(double[] array, ToDoubleFunction<BinaryStream> function) {
        return getArray(array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public double[] getArray(double[] array, ToDoubleFunction<BinaryStream> function, int maxLength) {
        int count = (int) getUnsignedVarInt();
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public double[] getArray(ToIntFunction<BinaryStream> lengthReader, double[] array, ToDoubleFunction<BinaryStream> function) {
        return getArray(lengthReader, array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public double[] getArray(ToIntFunction<BinaryStream> lengthReader, double[] array, ToDoubleFunction<BinaryStream> function, int maxLength) {
        int count = lengthReader.applyAsInt(this);
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    public double[] getArray(int length, double[] array, ToDoubleFunction<BinaryStream> function) {
        DoubleCollection collection = new DoubleArrayList();
        for (int i = 0; i < length; i++) {
            collection.add(function.applyAsDouble(this));
        }
        return collection.toArray(array);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public boolean[] getArray(boolean[] array, Object2BooleanFunction<BinaryStream> function) {
        return getArray(array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public boolean[] getArray(boolean[] array, Object2BooleanFunction<BinaryStream> function, int maxLength) {
        int count = (int) getUnsignedVarInt();
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    public boolean[] getArray(ToIntFunction<BinaryStream> lengthReader, boolean[] array, Object2BooleanFunction<BinaryStream> function) {
        return getArray(lengthReader, array, function, 4096);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public boolean[] getArray(ToIntFunction<BinaryStream> lengthReader, boolean[] array, Object2BooleanFunction<BinaryStream> function, int maxLength) {
        int count = lengthReader.applyAsInt(this);
        if (count > maxLength) {
            throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
        }
        return getArray(count, array, function);
    }

    public boolean[] getArray(int length, boolean[] array, Object2BooleanFunction<BinaryStream> function) {
        BooleanCollection collection = new BooleanArrayList();
        for (int i = 0; i < length; i++) {
            collection.add(function.getBoolean(this));
        }
        return collection.toArray(array);
    }

    public <T> void putArray(T[] array, BiConsumer<BinaryStream, T> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public <T> void putArray(T[] array, BiConsumer<BinaryStream, T> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public <T> void putArray(ObjIntConsumer<BinaryStream> lengthWriter, T[] array, BiConsumer<BinaryStream, T> consumer) {
        lengthWriter.accept(this, array.length);
        for (T element : array) {
            consumer.accept(this, element);
        }
    }

    public <T> void putArray(Collection<T> array, BiConsumer<BinaryStream, T> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public <T> void putArray(Collection<T> array, BiConsumer<BinaryStream, T> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public <T> void putArray(ObjIntConsumer<BinaryStream> lengthWriter, Collection<T> array, BiConsumer<BinaryStream, T> consumer) {
        lengthWriter.accept(this, array.size());
        for (T element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(byte[] array, ObjectByteBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(byte[] array, ObjectByteBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, byte[] array, ObjectByteBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.length);
        for (byte element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(ByteCollection array, ObjectByteBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(ByteCollection array, ObjectByteBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, ByteCollection array, ObjectByteBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.size());
        for (byte element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(short[] array, ObjectShortBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(short[] array, ObjectShortBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, short[] array, ObjectShortBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.length);
        for (short element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(ShortCollection array, ObjectShortBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(ShortCollection array, ObjectShortBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, ShortCollection array, ObjectShortBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.size());
        for (short element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(char[] array, ObjectCharBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(char[] array, ObjectCharBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, char[] array, ObjectCharBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.length);
        for (char element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(CharCollection array, ObjectCharBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(CharCollection array, ObjectCharBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, CharCollection array, ObjectCharBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.size());
        for (char element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(int[] array, ObjIntConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(int[] array, ObjIntConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, int[] array, ObjIntConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.length);
        for (int element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(IntCollection array, ObjIntConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(IntCollection array, ObjIntConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, IntCollection array, ObjIntConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.size());
        for (int element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(long[] array, ObjLongConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(long[] array, ObjLongConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, long[] array, ObjLongConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.length);
        for (long element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(LongCollection array, ObjLongConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(LongCollection array, ObjLongConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, LongCollection array, ObjLongConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.size());
        for (long element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(float[] array, ObjectFloatBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(float[] array, ObjectFloatBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, float[] array, ObjectFloatBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.length);
        for (float element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(FloatCollection array, ObjectFloatBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(FloatCollection array, ObjectFloatBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, FloatCollection array, ObjectFloatBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.size());
        for (float element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(double[] array, ObjDoubleConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(double[] array, ObjDoubleConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, double[] array, ObjDoubleConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.length);
        for (double element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(DoubleCollection array, ObjDoubleConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(DoubleCollection array, ObjDoubleConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, DoubleCollection array, ObjDoubleConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.size());
        for (double element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(boolean[] array, ObjectBooleanBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(boolean[] array, ObjectBooleanBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, boolean[] array, ObjectBooleanBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.length);
        for (boolean element : array) {
            consumer.accept(this, element);
        }
    }

    public void putArray(BooleanCollection array, ObjectBooleanBiConsumer<BinaryStream> consumer) {
        putArray(BinaryStream::putUnsignedVarInt, array, consumer);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than max length
     */
    public void putArray(BooleanCollection array, ObjectBooleanBiConsumer<BinaryStream> consumer, int maxLength) {
        putArray((stream, count) -> {
            if (count > maxLength) {
                throw new IndexOutOfBoundsException("array length exceeds max limit: " + count + " > " + maxLength);
            }
            stream.putUnsignedVarInt(count);
        }, array, consumer);
    }

    public void putArray(ObjIntConsumer<BinaryStream> lengthWriter, BooleanCollection array, ObjectBooleanBiConsumer<BinaryStream> consumer) {
        lengthWriter.accept(this, array.size());
        for (boolean element : array) {
            consumer.accept(this, element);
        }
    }

    public <T> T getEnum(Function<String, T> function) {
        return function.apply(getString());
    }

    public <T> void putEnum(T value, Function<T, String> function) {
        putString(function.apply(value));
    }

    @Nullable
    public <T> T getOptionalEnum(Function<String, T> function) {
        return getOptional(stream -> stream.getEnum(function));
    }

    public <T> void putOptionalEnum(@Nullable T value, Function<T, String> function) {
        putOptional(value, (stream, obj) -> stream.putEnum(obj, function));
    }

    @Nullable
    public <T> T getOptional(Function<BinaryStream, T> function) {
        return getOptional(function, null);
    }

    public <T> T getOptional(Function<BinaryStream, T> function, @Nullable T defaultValue) {
        return getBoolean() ? function.apply(this) : defaultValue;
    }

    public <T> void putOptional(T obj, BiConsumer<BinaryStream, T> consumer) {
        if (obj == null) {
            putBoolean(false);
            return;
        }

        putBoolean(true);
        consumer.accept(this, obj);
    }

    public <T> void putOptional(boolean present, T obj, BiConsumer<BinaryStream, T> consumer) {
        putBoolean(present);
        if (!present) {
            return;
        }
        consumer.accept(this, obj);
    }

    public void putOptional(boolean present, byte obj, ObjectByteBiConsumer<BinaryStream> consumer) {
        putBoolean(present);
        if (!present) {
            return;
        }
        consumer.accept(this, obj);
    }

    public void putOptional(boolean present, short obj, ObjectShortBiConsumer<BinaryStream> consumer) {
        putBoolean(present);
        if (!present) {
            return;
        }
        consumer.accept(this, obj);
    }

    public void putOptional(boolean present, char obj, ObjectCharBiConsumer<BinaryStream> consumer) {
        putBoolean(present);
        if (!present) {
            return;
        }
        consumer.accept(this, obj);
    }

    public void putOptional(boolean present, int obj, ObjIntConsumer<BinaryStream> consumer) {
        putBoolean(present);
        if (!present) {
            return;
        }
        consumer.accept(this, obj);
    }

    public void putOptional(boolean present, long obj, ObjLongConsumer<BinaryStream> consumer) {
        putBoolean(present);
        if (!present) {
            return;
        }
        consumer.accept(this, obj);
    }

    public void putOptional(boolean present, float obj, ObjectFloatBiConsumer<BinaryStream> consumer) {
        putBoolean(present);
        if (!present) {
            return;
        }
        consumer.accept(this, obj);
    }

    public void putOptional(boolean present, double obj, ObjDoubleConsumer<BinaryStream> consumer) {
        putBoolean(present);
        if (!present) {
            return;
        }
        consumer.accept(this, obj);
    }

    public void putOptional(boolean present, boolean obj, ObjectBooleanBiConsumer<BinaryStream> consumer) {
        putBoolean(present);
        if (!present) {
            return;
        }
        consumer.accept(this, obj);
    }

    public boolean isReadable(int length) {
        return count - offset >= length;
    }

    public boolean feof() {
        return this.offset < 0 || this.offset >= this.buffer.length;
    }

    private void ensureCapacity(int minCapacity) {
        // overflow-conscious code
        if (minCapacity - buffer.length > 0) {
            grow(minCapacity);
        }
    }

    private void grow(int minCapacity) {
        // overflow-conscious code
        int oldCapacity = buffer.length;
        int newCapacity = oldCapacity << 1;

        if (newCapacity - minCapacity < 0) {
            newCapacity = minCapacity;
        }

        if (newCapacity - MAX_ARRAY_SIZE > 0) {
            newCapacity = hugeCapacity(minCapacity);
        }
        this.buffer = Arrays.copyOf(buffer, newCapacity);
    }

    private static int hugeCapacity(int minCapacity) {
        if (minCapacity < 0) { // overflow
            throw new OutOfMemoryError();
        }
        return (minCapacity > MAX_ARRAY_SIZE) ?
                Integer.MAX_VALUE :
                MAX_ARRAY_SIZE;
    }
}
