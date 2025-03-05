import java.io.Console;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

public class App {

    public static void main(String[] args) {
        // Get the console for secure password input.
        Console console = System.console();
        if (console == null) {
            System.err.println("No console available. Run the application from a proper terminal.");
            System.exit(1);
        }
        
        // Prompt for the vault password (without echoing)
        char[] vaultPasswordChars = console.readPassword("Vault Password: ");
        String vaultPassword = new String(vaultPasswordChars);

        // Initialize the vault
        Vault vault = null;
        try {
            vault = new Vault(vaultPassword);
        } catch (Exception e) {
            System.err.println("Error initializing vault: " + e.getMessage());
            System.exit(1);
        }

        if (args.length < 1) {
            printUsage();
            System.exit(0);
        }

        String command = args[0];
        try {
            switch (command) {
                case "--add":
                case "-a":
                    handleAddCommand(args, console, vault);
                    break;
                case "--lookup-pass":
                case "-p":
                    if (args.length < 2) {
                        System.err.println("Service name required for lookup.");
                        printUsage();
                        System.exit(1);
                    }
                    String serviceForPass = args[1];
                    String[] passResult = vault.lookupPasswordEntry(serviceForPass);
                    if (passResult != null) {
                        System.out.println("User Name: " + passResult[0]);
                        System.out.println("Password: " + passResult[1]);
                    }
                    break;
                case "--lookup-key":
                case "-r":
                    if (args.length < 2) {
                        System.err.println("Service name required for key lookup.");
                        printUsage();
                        System.exit(1);
                    }
                    String serviceForKey = args[1];
                    String privateKey = vault.lookupPrivateKeyEntry(serviceForKey);
                    if (privateKey != null) {
                        System.out.println("Private Key: " + privateKey);
                    }
                    break;
                default:
                    System.err.println("Unknown command: " + command);
                    printUsage();
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Error executing command: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Handles the "--add" command. Depending on the options provided,
     * it either adds a password entry or a private key entry.
     */
    private static void handleAddCommand(String[] args, Console console, Vault vault) throws Exception {
        String service = null;
        String user = null;
        String key = null;
        int genLength = 0;
        boolean keygen = false;
        boolean genOption = false;  // Flag to track if --gen was specified

        // Parse options following the --add command.
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--service":
                case "-s":
                    if (i + 1 < args.length) {
                        service = args[++i];
                    }
                    break;
                case "--user":
                case "-u":
                    if (i + 1 < args.length) {
                        user = args[++i];
                    }
                    break;
                case "--key":
                case "-k":
                    if (i + 1 < args.length) {
                        key = args[++i];
                    }
                    break;
                case "--gen":
                case "-g":
                    genOption = true;  // Mark that --gen was specified
                    if (i + 1 < args.length) {
                        try {
                            genLength = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid password length provided.");
                            System.exit(1);
                        }
                    }
                    break;
                case "--keygen":
                case "-c":
                    keygen = true;
                    break;
                default:
                    System.err.println("Unknown option: " + args[i]);
                    printUsage();
                    System.exit(1);
            }
        }

        if (service == null) {
            System.err.println("Service name is required.");
            printUsage();
            System.exit(1);
        }
        
        // Determine which type of account to add
        if (keygen) {
            // Generate a new ElGamal key pair and store the private key
            PrivateKeyService pkService = new PrivateKeyService();
            try {
                // Generate the key pair and get it returned
                KeyPair keyPair = pkService.generateAndStoreElGamalKeyPair(service);
                
                // Convert private key to Base64 string
                String privateKeyStr = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
                
                // Store the private key in the vault
                vault.addPrivateKeyEntry(service, privateKeyStr);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                System.err.println("Error generating key pair: " + e.getMessage());
                System.exit(1);
            }
        } else if (key != null) {
            // Add a provided private key entry to the vault
            vault.addPrivateKeyEntry(service, key);
        } else if (user != null) {
            // Check if password generation was requested
            if (genOption) {
                // Validate the password length
                if (genLength <= 0) {
                    System.err.println("Password length must be greater than zero.");
                    System.exit(1);
                }
                
                try {
                    // Create ServiceUserPassword object for password generation
                    ServiceUserPassword sup = new ServiceUserPassword(service, user, genLength);
                    vault.addPasswordEntry(service, user, sup.getPassword());
                } catch (IllegalArgumentException e) {
                    // This catches the exception thrown by ServiceUserPassword for invalid length
                    System.err.println(e.getMessage());
                    System.exit(1);
                }
            } else {
                // Prompt the user to enter a password (without echoing)
                char[] servicePassChars = console.readPassword("Service Password: ");
                String servicePass = new String(servicePassChars);
                vault.addPasswordEntry(service, user, servicePass);
            }
        } else {
            System.err.println("For adding an account, either a username or a key must be specified.");
            printUsage();
            System.exit(1);
        }
    }

    /**
     * Prints the usage instructions.
     */
    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  --add --service <name> --user <uname> [--gen <len>]");
        System.out.println("  --add --service <name> --key <key>");
        System.out.println("  --add --service <name> --keygen");
        System.out.println("  --lookup-pass <name>");
        System.out.println("  --lookup-key <name>");
    }
}