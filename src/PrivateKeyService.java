import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PrivateKeyService {
    private Map<String, String> serviceKeyPair; // Stores Base64-encoded private keys

    public PrivateKeyService() {
        Security.addProvider(new BouncyCastleProvider());
        serviceKeyPair = new HashMap<>();
    }

    /**
     * Stores the provided private key (Base64 encoded) for the given service.
     */
    public void addPrivateKey(String serviceName, PrivateKey privateKey) {
        String encodedKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        serviceKeyPair.put(serviceName, encodedKey);
        System.out.println("Private key stored successfully for service: " + serviceName);
    }

    /**
     * Generates an ElGamal key pair with a 512-bit key size.
     */
    public KeyPair generateElGamalKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
        keyGen.initialize(512); // Generate a 512-bit key pair as per guidelines
        return keyGen.generateKeyPair();
    }

    /**
     * Generates an ElGamal key pair, outputs the public key as a Base64 string,
     * and stores the private key for the given service.
     */
    public KeyPair generateAndStoreElGamalKeyPair(String serviceName) throws Exception {
        KeyPair keyPair = generateElGamalKeyPair();
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        System.out.println("Public Key for service " + serviceName + ": " + publicKeyBase64);
        addPrivateKey(serviceName, keyPair.getPrivate());
        return keyPair;
    }

    /**
     * Looks up the stored private key for the given service.
     * @return the Base64 encoded private key, or null if not found.
     */
    public String lookupPrivateKey(String serviceName) {
        if (serviceKeyPair.containsKey(serviceName)) {
            return serviceKeyPair.get(serviceName);
        } else {
            System.out.println("\n--- Private key not found for service: " + serviceName + " ---\n");
            return null;
        }
    }
}
