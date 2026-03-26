package org.itxtech.nemisys.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import lombok.extern.log4j.Log4j2;
import tools.jackson.core.type.TypeReference;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

@Log4j2
public final class EncryptionUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final KeyPairGenerator KEY_PAIR_GEN;

    private static final String DISCOVERY_ENDPOINT = "https://client.discovery.minecraft-services.net/api/v1.0/discovery/MinecraftPE/builds/1.0.0.0";
    private static final JWTProcessor<SecurityContext> JWT_PROCESSOR = Utils.make(() -> {
        Map<String, Object> discoveryConfiguration = fetchDiscoveryConfiguration();
        return createJwtProcessor(discoveryConfiguration, fetchOpenIdConfiguration(discoveryConfiguration));
    });

    static {
        // Since Java 8u231, secp384r1 is deprecated and will throw an exception.
        String namedGroups = System.getProperty("jdk.tls.namedGroups");
        System.setProperty("jdk.tls.namedGroups", namedGroups == null || namedGroups.isEmpty() ? "secp384r1" : namedGroups + ", secp384r1");

        try {
            KEY_PAIR_GEN = KeyPairGenerator.getInstance("EC");
            KEY_PAIR_GEN.initialize(new ECGenParameterSpec("secp384r1"));
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new AssertionError("Unable to initialize required encryption", e);
        }
    }

    private static Map<String, Object> fetchDiscoveryConfiguration() {
        try {
            HttpURLConnection connection = (HttpURLConnection) URI.create(DISCOVERY_ENDPOINT).toURL().openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.connect();
            if (connection.getResponseCode() != 200) {
                throw new IOException("Failed to fetch discovery data: " + connection.getResponseMessage());
            }
            try (InputStream stream = connection.getInputStream();
                 InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                return JsonUtil.COMMON_JSON_MAPPER.readValue(reader, new TypeReference<>(){});
            }
        } catch (IOException e) {
            log.warn("Unable to fetch discovery data from {}", DISCOVERY_ENDPOINT, e);

            try (InputStream stream = EncryptionUtils.class.getResourceAsStream("/.well-known/discovery.json");
                 InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                return JsonUtil.TRUSTED_JSON_MAPPER.readValue(reader, new TypeReference<>(){});
            } catch (IOException ex) {
                throw new AssertionError("Unable to load discovery data from jar:/.well-known/discovery.json", e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> getAuthEnvironment(Map<String, Object> discoveryConfiguration) {
        Map<String, Object> result = (Map<String, Object>) discoveryConfiguration.get("result");

        if (result == null) {
            throw new AssertionError("Discovery data does not contain 'result' key: " + discoveryConfiguration);
        }
        Map<String, Object> environments = (Map<String, Object>) result.get("serviceEnvironments");
        if (environments == null) {
            throw new AssertionError("Discovery data does not contain 'serviceEnvironments' key: " + result);
        }
        Map<String, Object> authEnv = (Map<String, Object>) environments.get("auth");
        if (authEnv == null) {
            throw new AssertionError("Discovery data does not contain 'auth' environment: " + environments);
        }
        Map<String, Object> prodEnv = (Map<String, Object>) authEnv.get("prod");
        if (prodEnv == null) {
            throw new AssertionError("Discovery data does not contain 'prod' environment: " + authEnv);
        }
        return prodEnv;
    }

    private static String getServiceUri(Map<String, Object> discoveryConfiguration) {
        if (!(getAuthEnvironment(discoveryConfiguration).get("serviceUri") instanceof String uri)) {
            throw new AssertionError("Discovery data does not contain 'serviceUri' key in 'prod' environment");
        }
        return uri;
    }

    private static String getTitleId(Map<String, Object> discoveryConfiguration) {
        if (!(getAuthEnvironment(discoveryConfiguration).get("playfabTitleId") instanceof String titleId)) {
            throw new AssertionError("Discovery data does not contain 'playfabTitleId' key in 'prod' environment");
        }
        return titleId;
    }

    // https://authorization.franchise.minecraft-services.net/.well-known/openid-configuration
    private static Map<String, Object> fetchOpenIdConfiguration(Map<String, Object> discoveryConfiguration) {
        String openIdConfigUrl = getServiceUri(discoveryConfiguration) + "/.well-known/openid-configuration";
        try {
            HttpURLConnection connection = (HttpURLConnection) URI.create(openIdConfigUrl).toURL().openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.connect();
            if (connection.getResponseCode() != 200) {
                throw new IOException("Failed to fetch OpenID configuration: " + connection.getResponseMessage());
            }
            try (InputStream stream = connection.getInputStream();
                 InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                return JsonUtil.COMMON_JSON_MAPPER.readValue(reader, new TypeReference<>(){});
            }
        } catch (IOException e) {
            log.warn("Unable to fetch OpenID configuration from {}", openIdConfigUrl, e);

            try (InputStream stream = EncryptionUtils.class.getResourceAsStream("/.well-known/openid-configuration.json");
                 InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                return JsonUtil.TRUSTED_JSON_MAPPER.readValue(reader, new TypeReference<>(){});
            } catch (IOException ex) {
                throw new AssertionError("Unable to load OpenID configuration from jar:/.well-known/openid-configuration.json", e);
            }
        }
    }

    private static String getJwksUrl(Map<String, Object> openIdConfiguration) {
        String jwksUrl = (String) openIdConfiguration.get("jwks_uri");
        if (jwksUrl == null || jwksUrl.isEmpty()) {
            throw new AssertionError("OpenID configuration does not contain 'jwks_uri' key: " + openIdConfiguration);
        }
        return jwksUrl;
        // https://authorization.franchise.minecraft-services.net/.well-known/keys
    }

    private static String getIssuer(Map<String, Object> openIdConfiguration) {
        String issuer = (String) openIdConfiguration.get("issuer");
        if (issuer == null || issuer.isEmpty()) {
            throw new AssertionError("OpenID configuration does not contain 'issuer' key: " + openIdConfiguration);
        }
        return issuer;
        // https://authorization.franchise.minecraft-services.net/
    }

    private static JWKSource<SecurityContext> createJwkSource(Map<String, Object> openIdConfiguration) {
        String jwksUrl = getJwksUrl(openIdConfiguration);
        try (InputStream stream = EncryptionUtils.class.getResourceAsStream("/.well-known/keys.json")) {
            return JWKSourceBuilder.create(URI.create(jwksUrl).toURL(), new DefaultResourceRetriever(5000, 5000))
                    .cache(2 * 60 * 60 * 1000, JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT)
                    .retrying(true)
                    .refreshAheadCache(3 * 60 * 1000, true)
                    .outageTolerant(true)
                    .failover(new ImmutableJWKSet<>(JWKSet.parse(new String(stream.readAllBytes(), StandardCharsets.UTF_8))))
                    .build();
        } catch (IOException | ParseException e) {
            throw new AssertionError("Unable to create JWK source from " + jwksUrl, e);
        }
    }

    private static JWTProcessor<SecurityContext> createJwtProcessor(Map<String, Object> discoveryConfiguration, Map<String, Object> openIdConfiguration) {
        ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, createJwkSource(openIdConfiguration)));
        processor.setJWSTypeVerifier(DefaultJOSEObjectTypeVerifier.JWT);
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>("api://auth-minecraft-services/multiplayer", new JWTClaimsSet.Builder()
                .issuer(getIssuer(openIdConfiguration))
                .claim("ipt", "PlayFab")
                .claim("tid", getTitleId(discoveryConfiguration)) // "20CA2"
                .build(),
                Set.of(
                        JWTClaimNames.SUBJECT,
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME,
                        "xid",
                        "xname",
                        "mid",
                        "pfcd",
                        "cpk"
                )));
        return processor;
    }

    public static JWTClaimsSet validateToken(JWT jwt) throws BadJOSEException, JOSEException {
        return JWT_PROCESSOR.process(jwt, null);
    }

    /**
     * Generate EC public key from base 64 encoded string
     *
     * @param b64 base 64 encoded key
     * @return key generated
     * @throws NoSuchAlgorithmException runtime does not support the EC key spec
     * @throws InvalidKeySpecException  input does not conform with EC key spec
     */
    public static ECPublicKey generateKey(String b64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }

    /**
     * Create EC key pair to be used for handshake and encryption
     *
     * @return EC KeyPair
     */
    public static KeyPair createKeyPair() {
        return KEY_PAIR_GEN.generateKeyPair();
    }

    /**
     * Sign JWS object with a given private key.
     *
     * @param jws object to be signed
     * @param key key to sign object with
     * @throws JOSEException invalid key provided
     */
    public static void signJwt(JWSObject jws, ECPrivateKey key) throws JOSEException {
        jws.sign(new ECDSASigner(key, Curve.P_384));
    }

    /**
     * Generate the secret key used to encrypt the connection
     *
     * @param localPrivateKey local private key
     * @param remotePublicKey remote public key
     * @param token           token generated or received from the server
     * @return secret key used to encrypt connection
     * @throws InvalidKeyException keys provided are not EC spec
     */
    public static SecretKey getSecretKey(PrivateKey localPrivateKey, PublicKey remotePublicKey, byte[] token) throws InvalidKeyException {
        byte[] sharedSecret = getEcdhSecret(localPrivateKey, remotePublicKey);

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }

        digest.update(token);
        digest.update(sharedSecret);
        byte[] secretKeyBytes = digest.digest();
        return new SecretKeySpec(secretKeyBytes, "AES");
    }

    private static byte[] getEcdhSecret(PrivateKey localPrivateKey, PublicKey remotePublicKey) throws InvalidKeyException {
        KeyAgreement agreement;
        try {
            agreement = KeyAgreement.getInstance("ECDH");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }

        agreement.init(localPrivateKey);
        agreement.doPhase(remotePublicKey, true);
        return agreement.generateSecret();
    }

    /**
     * Create handshake JWS used in the {@link org.itxtech.nemisys.network.protocol.mcpe.ServerToClientHandshakePacket}
     * which completes the encryption handshake.
     *
     * @param serverKeyPair used to sign the JWT
     * @param x5u           X.509 certificate URL of the server public key
     * @param token         salt for the encryption handshake
     * @return signed JWS object
     * @throws JOSEException invalid key pair provided
     */
    public static JWSObject createHandshakeJwt(KeyPair serverKeyPair, URI x5u, byte[] token) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("salt", Base64.getEncoder().encodeToString(token)).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES384).x509CertURL(x5u).build(), claimsSet);

        signJwt(jwt, (ECPrivateKey) serverKeyPair.getPrivate());

        return jwt;
    }

    /**
     * Generate 16 bytes of random data for the handshake token using a {@link SecureRandom}
     *
     * @return 16 byte token
     */
    public static byte[] generateRandomToken() {
        byte[] token = new byte[16];
        SECURE_RANDOM.nextBytes(token);
        return token;
    }

    public static Cipher createCipher(boolean gcm, boolean encrypt, SecretKey key) {
        try {
            byte[] iv;
            String transformation;
            if (gcm) {
                iv = new byte[16];
                System.arraycopy(key.getEncoded(), 0, iv, 0, 12);
                iv[15] = 2;
                transformation = "AES/CTR/NoPadding";
            } else {
                iv = Arrays.copyOf(key.getEncoded(), 16);
                transformation = "AES/CFB8/NoPadding";
            }
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new AssertionError("Unable to initialize required encryption", e);
        }
    }

    public static void init() {
    }

    private EncryptionUtils() {
    }
}
