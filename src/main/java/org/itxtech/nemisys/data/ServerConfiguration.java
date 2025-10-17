package org.itxtech.nemisys.data;

import lombok.Builder;
import lombok.Builder.Default;
import lombok.Value;
import org.itxtech.nemisys.network.CompressionAlgorithm;

@Builder
@Value
public class ServerConfiguration {
    String serverIp;
    int serverPort;
    String password;
    String motd;
    boolean plusOneMaxCount;
    boolean xboxAuth;
    @Default
    byte compressionAlgorithm = CompressionAlgorithm.SNAPPY;
}
