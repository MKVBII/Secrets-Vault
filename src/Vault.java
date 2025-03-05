import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

import org.bouncycastle.crypto.generators.SCrypt;

public class Vault {

    // Constants for file and crypto parameters
    private static final String VAULT_FILE = "vault.json";
    private static final int AES_KEY_SIZE = 16;          // 16 bytes = 128 bits
    private static final int GCM_IV_LENGTH = 12;         // 12 bytes recommended for GCM
    private static final int GCM_TAG_LENGTH = 128;       // tag length in bits
    private static final int SCRYPT_COST_FACTOR = 2048;  // SCrypt cost factor (aka N)
    private static final int SCRYPT_BLOCK_SIZE = 8;      // SCrypt block size (aka r)
    private static final int SCRYPT_P_FACTOR = 1;        // SCrypt parallelization (aka p)
    private byte[] salt;                                 // salt (generated once)

    // In-memory representation of the vault (decrypted JSON with secret entries)
    private JSONObject vaultData;

    // The decrypted vault key used to encrypt/decrypt vaultData
    private SecretKey vaultKey;

    // Secure random instance for generating keys, IVs, and salt
    private SecureRandom secureRandom = new SecureRandom();

    // The vault password (used to derive the root key)
    private String vaultPassword;

    /**
     * Constructor. Attempts to load (and unseal) the vault using the provided vault password.
     * If the vault file does not exist, a new vault is created automatically.
     * A shutdown hook is added to seal the vault upon exit.
     */
    public Vault(String vaultPassword) throws Exception {
        this.vaultPassword = vaultPassword;
        loadVault();
        // Ensure vault is sealed on exit
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                sealVault();
            } catch (Exception e) {
                System.err.println("\n--- Error sealing vault on exit: " + e.getMessage() + " ---\n");
            }
        }));
    }

    /**
     * Loads the vault from disk. If vault.json does not exist, creates a new vault.
     */
    private void loadVault() throws Exception {
        if (!Files.exists(Paths.get(VAULT_FILE))) {
            createNewVault();
        } else {
            unsealVault();
        }
    }

    /**
     * Creates a new vault.
     * - Generates a random salt.
     * - Derives the root key from the vault password using SCrypt.
     * - Generates a new random vault key.
     * - Initializes an empty vault (with "passwords" and "privkeys" arrays).
     * - Seals (encrypts) the vault and writes it to vault.json.
     */
    private void createNewVault() throws Exception {
        System.out.println("Creating new Vault...");
        // Generate a new salt (16 bytes) and encode it as Base64
        salt = new byte[16];
        secureRandom.nextBytes(salt);
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        System.out.println("Salt generated.");
    
        // Derive root key from vaultPassword using SCrypt
        byte[] rootKeyBytes = SCrypt.generate(vaultPassword.getBytes("UTF-8"), salt,
                SCRYPT_COST_FACTOR, SCRYPT_BLOCK_SIZE, SCRYPT_P_FACTOR, AES_KEY_SIZE);
        SecretKey rootKey = new SecretKeySpec(rootKeyBytes, "AES");
        System.out.println("Root key derived.");
    
        // Generate a new random vault key
        byte[] vaultKeyBytes = new byte[AES_KEY_SIZE];
        secureRandom.nextBytes(vaultKeyBytes);
        vaultKey = new SecretKeySpec(vaultKeyBytes, "AES");
        System.out.println("Vault key generated.");
    
        // Initialize an empty vaultData object with required arrays
        vaultData = new JSONObject();
        vaultData.put("passwords", new JSONArray());
        vaultData.put("privkeys", new JSONArray());
        
        System.out.println("Vault data initialized.");
    
        // Seal the vault and write to disk
        sealVaultHelper(saltBase64, rootKey);
        System.out.println("New vault created.");
    }

    /**
     * Unseals (decrypts) the vault from disk.
     * - Reads vault.json.
     * - Derives the root key from the vault password and stored salt.
     * - Decrypts the vault key using the root key.
     * - Decrypts the vault data using the vault key.
     */
    private void unsealVault() throws Exception {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> sealedVaultMap;
            
            // Read the vault file into a Map
            try {
                sealedVaultMap = mapper.readValue(new File(VAULT_FILE), 
                    new TypeReference<Map<String, Object>>() {});
            } catch (Exception e) {
                System.err.println("\n--- Error reading vault file: " + e.getMessage() + " ---\n");
                throw e;
            }

            // Retrieve and decode the salt
            String saltBase64 = sealedVaultMap.get("salt").toString();
            salt = Base64.getDecoder().decode(saltBase64);
            System.out.println("Salt decoded.");

            // Derive root key using SCrypt
            byte[] rootKeyBytes = SCrypt.generate(vaultPassword.getBytes("UTF-8"), salt,
                    SCRYPT_COST_FACTOR, SCRYPT_BLOCK_SIZE, SCRYPT_P_FACTOR, AES_KEY_SIZE);
            SecretKey rootKey = new SecretKeySpec(rootKeyBytes, "AES");
            System.out.println("Root key derived.");

            // Decrypt the vault key - handle Map instead of JSONObject
            Map<String, Object> vaultKeyMap = (Map<String, Object>) sealedVaultMap.get("vaultKey");
            byte[] vaultKeyIv = Base64.getDecoder().decode(vaultKeyMap.get("iv").toString());
            byte[] encryptedVaultKey = Base64.getDecoder().decode(vaultKeyMap.get("key").toString());
            // No AAD for vault key decryption
            byte[] vaultKeyBytes = decryptData(vaultKeyIv, encryptedVaultKey, rootKey, null);
            vaultKey = new SecretKeySpec(vaultKeyBytes, "AES");
            System.out.println("Vault key decrypted.");

            // Decrypt the vault data - handle Map instead of JSONObject
            Map<String, Object> vaultDataEncMap = (Map<String, Object>) sealedVaultMap.get("vaultData");
            byte[] vaultDataIv = Base64.getDecoder().decode(vaultDataEncMap.get("iv").toString());
            byte[] vaultDataCiphertext = Base64.getDecoder().decode(vaultDataEncMap.get("ciphertext").toString());
            byte[] vaultDataBytes = decryptData(vaultDataIv, vaultDataCiphertext, vaultKey, null);

            String vaultDataJson = new String(vaultDataBytes, "UTF-8");            

            // Initialize with empty structure and modify it through proper methods
            vaultData = new JSONObject();
            vaultData.put("passwords", new JSONArray());
            vaultData.put("privkeys", new JSONArray());
            
            // Parse the decrypted JSON string into a Map
            Map<String, Object> vaultDataMap = mapper.readValue(vaultDataJson, 
                new TypeReference<Map<String, Object>>() {});
            
            // Handle passwords array
            if (vaultDataMap.containsKey("passwords")) {
                List<Map<String, Object>> passwordsList = (List<Map<String, Object>>) vaultDataMap.get("passwords");
                JSONArray passwordsArray = (JSONArray) vaultData.get("passwords");
                
                for (Map<String, Object> passEntry : passwordsList) {
                    JSONObject jsonEntry = new JSONObject();
                    for (Map.Entry<String, Object> field : passEntry.entrySet()) {
                        jsonEntry.put(field.getKey(), field.getValue());
                    }
                    passwordsArray.add(jsonEntry);
                }
            }
            
            // Handle privkeys array
            if (vaultDataMap.containsKey("privkeys")) {
                List<Map<String, Object>> privkeysList = (List<Map<String, Object>>) vaultDataMap.get("privkeys");
                JSONArray privkeysArray = (JSONArray) vaultData.get("privkeys");
                
                for (Map<String, Object> keyEntry : privkeysList) {
                    JSONObject jsonEntry = new JSONObject();
                    for (Map.Entry<String, Object> field : keyEntry.entrySet()) {
                        jsonEntry.put(field.getKey(), field.getValue());
                    }
                    privkeysArray.add(jsonEntry);
                }
            }
            
            System.out.println("Vault data decrypted and loaded.");

        } catch (Exception e) {
            System.err.println("\n--- Error unsealing vault: " + e.getMessage() + " ---\n");
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Seals the vault by encrypting its contents and writing to disk.
     */
    public void sealVault() throws Exception {
        try {
            // Re-read the existing salt
            if (salt == null) {
                if (Files.exists(Paths.get(VAULT_FILE))) {
                    // Read the salt from the existing vault file
                    ObjectMapper mapper = new ObjectMapper();
                    Map<String, Object> existingVault = mapper.readValue(new File(VAULT_FILE), 
                        new TypeReference<Map<String, Object>>() {});
                    String saltBase64 = existingVault.get("salt").toString();
                    salt = Base64.getDecoder().decode(saltBase64);
                } else {
                    salt = generateNewSalt();
                }
            }
            
            String saltBase64 = Base64.getEncoder().encodeToString(salt);

            // Derive root key using stored salt and vaultPassword
            byte[] rootKeyBytes = SCrypt.generate(vaultPassword.getBytes("UTF-8"), salt,
                    SCRYPT_COST_FACTOR, SCRYPT_BLOCK_SIZE, SCRYPT_P_FACTOR, AES_KEY_SIZE);
            SecretKey rootKey = new SecretKeySpec(rootKeyBytes, "AES");
            sealVaultHelper(saltBase64, rootKey);
            System.out.println("Vault sealed successfully.");
        } catch (Exception e) {
            System.err.println("\n--- Error sealing vault: " + e.getMessage() + " ---\n");
            e.printStackTrace();
            throw e;
        }
    }
    
    /**
     * Generates a new salt for SCrypt
     */
    private byte[] generateNewSalt() {
        byte[] newSalt = new byte[16];
        secureRandom.nextBytes(newSalt);
        return newSalt;
    }

    /**
     * Internal helper method to seal the vault.
     * Encrypts vaultData with the vault key and vault key with the root key, then writes the JSON structure.
     */
    private void sealVaultHelper(String saltBase64, SecretKey rootKey) throws Exception {
        System.out.println("Sealing vault...");
        
        // Convert vaultData to a JSON string using Jackson for proper JSON formatting
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> vaultDataMap = convertJSONObjectToMap(vaultData);
        String vaultDataString = mapper.writeValueAsString(vaultDataMap);
        
        byte[] vaultDataBytes = vaultDataString.getBytes("UTF-8");

        // Encrypt vaultData with the vault key (no AAD used here)
        EncryptionResult dataEncResult = encryptData(vaultDataBytes, vaultKey, null);
        // Encrypt the vault key with the root key (no AAD used)
        EncryptionResult keyEncResult = encryptData(vaultKey.getEncoded(), rootKey, null);

        // Build the final sealed JSON structure
        JSONObject sealedVault = new JSONObject();
        sealedVault.put("salt", saltBase64);
        
        JSONObject vaultKeyData = new JSONObject();
        vaultKeyData.put("iv", Base64.getEncoder().encodeToString(keyEncResult.iv));
        vaultKeyData.put("key", Base64.getEncoder().encodeToString(keyEncResult.ciphertext));
        sealedVault.put("vaultKey", vaultKeyData);
        
        JSONObject vaultDataEnc = new JSONObject();
        vaultDataEnc.put("iv", Base64.getEncoder().encodeToString(dataEncResult.iv));
        vaultDataEnc.put("ciphertext", Base64.getEncoder().encodeToString(dataEncResult.ciphertext));
        sealedVault.put("vaultData", vaultDataEnc);

        // Convert to standard Map for Jackson serialization
        Map<String, Object> sealedVaultMap = convertJSONObjectToMap(sealedVault);
        
        // Write to file using ObjectMapper for pretty printing
        Files.write(Paths.get(VAULT_FILE), 
            mapper.writerWithDefaultPrettyPrinter().writeValueAsString(sealedVaultMap).getBytes());
        System.out.println("Vault written to disk.");
    }

    /**
     * Helper method to convert JSONObject to standard Java Map for proper serialization
     */
    private Map<String, Object> convertJSONObjectToMap(JSONObject jsonObject) {
        Map<String, Object> map = new HashMap<>();
        for (String key : jsonObject.keySet()) {
            Object value = jsonObject.get(key);
            if (value instanceof JSONObject) {
                map.put(key, convertJSONObjectToMap((JSONObject) value));
            } else if (value instanceof JSONArray) {
                map.put(key, convertJSONArrayToList((JSONArray) value));
            } else {
                map.put(key, value);
            }
        }
        return map;
    }

    /**
     * Helper method to convert JSONArray to standard Java List for proper serialization
     */
    private List<Object> convertJSONArrayToList(JSONArray jsonArray) {
        List<Object> list = new ArrayList<>();
        for (int i = 0; i < jsonArray.size(); i++) {
            Object value = jsonArray.get(i);
            if (value instanceof JSONObject) {
                list.add(convertJSONObjectToMap((JSONObject) value));
            } else if (value instanceof JSONArray) {
                list.add(convertJSONArrayToList((JSONArray) value));
            } else {
                list.add(value);
            }
        }
        return list;
    }

    /**
     * Overloaded encryption method that accepts AAD.
     * If aad is non-null, it is provided to the cipher via updateAAD.
     */
    private EncryptionResult encryptData(byte[] plaintext, SecretKey key, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        byte[] ciphertext = cipher.doFinal(plaintext);
        EncryptionResult result = new EncryptionResult();
        result.iv = iv;
        result.ciphertext = ciphertext;
        return result;
    }

    /**
     * Overloaded decryption method that accepts AAD.
     */
    private byte[] decryptData(byte[] iv, byte[] ciphertext, SecretKey key, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(ciphertext);
    }

    // --- Vault Operations for Secret Entries ---

    /**
     * Adds a new password entry to the vault.
     * The plaintext password is encrypted with the vault key.
     * The service and user names are used as AAD (concatenated with a colon) to authenticate these values.
     */
    public void addPasswordEntry(String service, String user, String password) throws Exception {
        try {
            // Get the passwords array from vault data
            JSONArray passwords;
            if (vaultData.containsKey("passwords")) {
                passwords = (JSONArray) vaultData.get("passwords");
            } else {
                passwords = new JSONArray();
                vaultData.put("passwords", passwords);
            }
            
            // Create a new entry
            JSONObject entry = new JSONObject();
            entry.put("service", service);
            entry.put("user", user);
            
            // Use service and user as AAD (e.g., "service:user")
            String aadString = service + ":" + user;
            EncryptionResult encResult = encryptData(password.getBytes("UTF-8"), vaultKey, aadString.getBytes("UTF-8"));
            entry.put("iv", Base64.getEncoder().encodeToString(encResult.iv));
            entry.put("pass", Base64.getEncoder().encodeToString(encResult.ciphertext));
            
            // Add the entry directly to the JSONArray
            passwords.add(entry);
            
            sealVault();
            System.out.println("Password entry added for service: " + service);
        } catch (Exception e) {
            System.err.println("\n--- Error adding password entry: " + e.getMessage() + " ---\n");
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Looks up a password entry by service name.
     * Returns a string array where [0] is the user and [1] is the decrypted password.
     * The same AAD (service:user) is used during decryption.
     */
    public String[] lookupPasswordEntry(String service) throws Exception {
        try {
            if (!vaultData.containsKey("passwords")) {
                System.out.println("\n--- No passwords stored in vault. ---\n");
                return null;
            }
            
            JSONArray passwords = (JSONArray) vaultData.get("passwords");
            
            // Search for the entry matching the service name
            for (int i = 0; i < passwords.size(); i++) {
                JSONObject entry = (JSONObject) passwords.get(i);
                if (entry.get("service").toString().equals(service)) {
                    String user = entry.get("user").toString();
                    String aadString = service + ":" + user;
                    byte[] iv = Base64.getDecoder().decode(entry.get("iv").toString());
                    byte[] ciphertext = Base64.getDecoder().decode(entry.get("pass").toString());
                    byte[] passwordBytes = decryptData(iv, ciphertext, vaultKey, aadString.getBytes("UTF-8"));
                    String password = new String(passwordBytes, "UTF-8");
                    System.out.println("Password entry found for service: " + service);
                    return new String[]{user, password};
                }
            }
            
            System.out.println("\n--- Password entry not found for service: " + service + " ---\n");
            return null;
        } catch (Exception e) {
            System.err.println("\n--- Error looking up password entry: " + e.getMessage() + " ---\n");
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Adds a new private key entry to the vault.
     * The plaintext private key is encrypted with the vault key.
     * The service name is used as AAD to authenticate the entry.
     */
    public void addPrivateKeyEntry(String service, String privateKey) throws Exception {
        try {
            // Get the privkeys array from vault data
            JSONArray privkeys;
            if (vaultData.containsKey("privkeys")) {
                privkeys = (JSONArray) vaultData.get("privkeys");
            } else {
                privkeys = new JSONArray();
                vaultData.put("privkeys", privkeys);
            }
            
            // Create a new entry
            JSONObject entry = new JSONObject();
            entry.put("service", service);
            
            // Use service as AAD for private key entries
            EncryptionResult encResult = encryptData(privateKey.getBytes("UTF-8"), vaultKey, service.getBytes("UTF-8"));
            entry.put("iv", Base64.getEncoder().encodeToString(encResult.iv));
            entry.put("privkey", Base64.getEncoder().encodeToString(encResult.ciphertext));
            
            // Add the entry directly to the JSONArray
            privkeys.add(entry);
            
            sealVault();
            System.out.println("Private key entry added for service: " + service);
        } catch (Exception e) {
            System.err.println("\n--- Error adding private key entry: " + e.getMessage() + " ---\n");
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Looks up a private key entry by service name.
     * Returns the decrypted private key as a Base64 encoded string.
     * The service name is used as AAD during decryption.
     */
    public String lookupPrivateKeyEntry(String service) throws Exception {
        try {
            if (!vaultData.containsKey("privkeys")) {
                System.out.println("\n--- No private keys stored in vault. ---\n");
                return null;
            }
            
            JSONArray privkeys = (JSONArray) vaultData.get("privkeys");
            
            // Search for the entry matching the service name
            for (int i = 0; i < privkeys.size(); i++) {
                JSONObject entry = (JSONObject) privkeys.get(i);
                if (entry.get("service").toString().equals(service)) {
                    byte[] iv = Base64.getDecoder().decode(entry.get("iv").toString());
                    byte[] ciphertext = Base64.getDecoder().decode(entry.get("privkey").toString());
                    byte[] privateKeyBytes = decryptData(iv, ciphertext, vaultKey, service.getBytes("UTF-8"));
                    System.out.println("Private key entry found for service: " + service);
                    return new String(privateKeyBytes, "UTF-8");
                }
            }
            
            System.out.println("\n--- Private key entry not found for service: " + service + " ---\n");
            return null;
        } catch (Exception e) {
            System.err.println("\n--- Error looking up private key entry: " + e.getMessage() + " ---\n");
            e.printStackTrace();
            throw e;
        }
    }

    // Helper class to hold encryption result data
    private static class EncryptionResult {
        public byte[] iv;
        public byte[] ciphertext;
    }
}