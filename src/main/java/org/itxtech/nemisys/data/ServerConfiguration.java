package org.itxtech.nemisys.data;

import lombok.Builder;
import lombok.Value;

@Builder
@Value
public class ServerConfiguration {
    String serverIp;
    int serverPort;
    String password;
    String motd;
    boolean plusOneMaxCount;
    boolean xboxAuth;
}
