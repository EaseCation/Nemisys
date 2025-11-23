package org.itxtech.nemisys.network.protocol.mcpe;

import lombok.ToString;
import org.itxtech.nemisys.utils.BinaryStream;
import org.itxtech.nemisys.utils.Utils;

/**
 * Created on 15-10-13.
 */
@ToString
public class TextPacket extends DataPacket {

    public static final int NETWORK_ID = ProtocolInfo.TEXT_PACKET;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    public static final byte TYPE_RAW = 0;
    public static final byte TYPE_CHAT = 1;
    public static final byte TYPE_TRANSLATION = 2;
    public static final byte TYPE_POPUP = 3;
    public static final byte TYPE_JUKEBOX_POPUP = 4;
    public static final byte TYPE_TIP = 5;
    public static final byte TYPE_SYSTEM = 6;
    public static final byte TYPE_WHISPER = 7;
    public static final byte TYPE_ANNOUNCEMENT = 8;
    public static final byte TYPE_OBJECT = 9;
    public static final byte TYPE_OBJECT_WHISPER = 10;
    public static final byte TYPE_OBJECT_ANNOUNCEMENT = 11;

    public static final byte BODY_TYPE_MESSAGE_ONLY = 0;
    public static final byte BODY_TYPE_AUTHOR_AND_MESSAGE = 1;
    public static final byte BODY_TYPE_MESSAGE_AND_PARAMS = 2;

    public byte type;
    public boolean isLocalized = false;

    public String message = "";
    public String[] parameters = new String[0];
    public String primaryName = "";

    public String sendersXUID = "";
    public String platformIdString = "";
    public String filteredMessage = "";

    @Override
    public void decode(int protocol, boolean netease) {
    }

    @Override
    public void encode(int protocol, boolean netease) {
        this.reset(protocol);
        if (protocol < 897) {
            this.putByte(this.type);
        }
        this.putBoolean(this.isLocalized);
        switch (this.type) {
            case TYPE_CHAT:
            case TYPE_WHISPER:
            case TYPE_ANNOUNCEMENT:
                if (protocol >= 897) {
                    this.putUnsignedVarInt(BODY_TYPE_AUTHOR_AND_MESSAGE);
                    this.put(BODY_MAGIC_AUTHOR_AND_MESSAGE);
                    this.putByte(this.type);
                }
                this.putString(primaryName);
                this.putString(message);
                break;
            case TYPE_RAW:
            case TYPE_TIP:
            case TYPE_SYSTEM:
            case TYPE_OBJECT:
            case TYPE_OBJECT_WHISPER:
            case TYPE_OBJECT_ANNOUNCEMENT:
                if (protocol >= 897) {
                    this.putUnsignedVarInt(BODY_TYPE_MESSAGE_ONLY);
                    this.put(BODY_MAGIC_MESSAGE_ONLY);
                    this.putByte(this.type);
                }
                this.putString(message);
                break;
            case TYPE_TRANSLATION:
            case TYPE_POPUP:
            case TYPE_JUKEBOX_POPUP:
                if (protocol >= 897) {
                    this.putUnsignedVarInt(BODY_TYPE_MESSAGE_AND_PARAMS);
                    this.put(BODY_MAGIC_MESSAGE_AND_PARAMS);
                    this.putByte(this.type);
                }
                this.putString(this.message);
                this.putUnsignedVarInt(this.parameters.length);
                for (String parameter : this.parameters) {
                    this.putString(parameter);
                }
                break;
        }
        this.putString(sendersXUID);
        this.putString(platformIdString);
        if (protocol >= 685) {
            this.putString(filteredMessage);
        }

        if (netease && protocol >= 410) { // netease only
            if (type == TYPE_CHAT || type == TYPE_POPUP) {
                this.putString("");
            }
        }
    }

    @Override
    public void tryEncode(int protocol, boolean netease) {
        if (!this.isEncoded) {
            this.isEncoded = true;
            this.encode(protocol, netease);
        }
    }

    private static final byte[] BODY_MAGIC_MESSAGE_ONLY = Utils.make(() -> {
        BinaryStream stream = new BinaryStream();
        stream.putString("raw");
        stream.putString("tip");
        stream.putString("systemmessage");
        stream.putString("textobjectwhisper");
        stream.putString("textobjectannouncement");
        stream.putString("textobject");
        return stream.getBuffer();
    });
    private static final byte[] BODY_MAGIC_AUTHOR_AND_MESSAGE = Utils.make(() -> {
        BinaryStream stream = new BinaryStream();
        stream.putString("chat");
        stream.putString("whisper");
        stream.putString("announcement");
        return stream.getBuffer();
    });
    private static final byte[] BODY_MAGIC_MESSAGE_AND_PARAMS = Utils.make(() -> {
        BinaryStream stream = new BinaryStream();
        stream.putString("translate");
        stream.putString("popup");
        stream.putString("jukeboxpopup");
        return stream.getBuffer();
    });
}
