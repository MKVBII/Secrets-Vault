import java.security.SecureRandom;

public class ServiceUserPassword {
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#$%!&*@?";
    private static final SecureRandom random = new SecureRandom();

    private String serviceName;
    private String username;
    private String password;

    /**
     * Constructs an instance that generates a random password for the given service and username.
     * If passwordLength is less than 7, a warning is displayed.
     *
     * @param serviceName the service for which the password is generated
     * @param username the username associated with the service
     * @param passwordLength the desired length of the password
     */
    public ServiceUserPassword(String serviceName, String username, int passwordLength) {
        if (passwordLength <= 0) {
            throw new IllegalArgumentException("\n--- Password length must be greater than zero. ---\n");
        } else if (passwordLength < 7) {
            System.out.println("Warning: Password under 7 characters may be weaker");
        }
        this.serviceName = serviceName;
        this.username = username;
        this.password = generateRandomPassword(passwordLength);
    }

    /**
     * Helper method to generate a random password.
     *
     * @param length the length of the password
     * @return the generated password
     */
    private String generateRandomPassword(int length) {
        StringBuilder passwordBuilder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            passwordBuilder.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        System.out.println("Password generated for " + serviceName);
        return passwordBuilder.toString();
    }

    public String getServiceName() {
        return serviceName;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
