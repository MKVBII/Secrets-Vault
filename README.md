# Project_2_The_Vault

Ivan Zivlak . . . . He's in a better place😞
    
Jack Pelitier

Michael Brown

Implementation of a secrets vault software that stores usernames and passswords for services (websites) in a protected centralized repository so that secrets are note stored across a system ("secrets sprawl"). 

Real World Implementations: 
- Hashicorp Vault
- AWS Secrets Manager
- Kapersky Vault
- LastPass Vault

Operations:
- Add a new service name, username, and password triple

- Lookup a user's name-password pair for a given website

- Add a new service name and user name with a randomly generated password of specific length

- Add a new service name and private key pair 

- Lookup an ElGamal private key given a service name and putput as a Base64 encoded string

- Add a new service name and private key with a freshly generated 512-bit ElGamal key pair with the public key outputted to the screen as a Base 64 string



All Passwords (except for auto generated ones): password

TESTING ✅
# Commands to test functionality required by the project description:


1. Initial Vault Creation and Basic Password Storage ✅
First, create the vault and add a simple password entry:
# java -cp "bin:lib/*:." App --add --service gmail --user john.doe@gmail.com
Enter your vault password when prompted, and then enter a service password when prompted.

2. Verify Password Retrieval Works ✅
Next, confirm you can retrieve the password you just stored:
# java -cp "bin:lib/*:." App --lookup-pass gmail
Enter your vault password when prompted. This should display the username and password for the gmail service.

3. Test Auto-Generated Password Feature ✅
Add a password using the auto-generation feature with a sufficient length:
# java -cp "bin:lib/*:." App --add --service twitter --user twitteruser --gen 12
Enter your vault password when prompted. The system should generate a 12-character password.

4. Verify Auto-Generated Password Retrieval ✅
Confirm you can retrieve the auto-generated password:
# java -cp "bin:lib/*:." App --lookup-pass twitter
Enter your vault password when prompted. You should see the username and the generated password.

5. Test Password Length Warning ✅
Test the warning for short passwords:
# java -cp "bin:lib/*:." App --add --service short --user shortuser --gen 5
Enter your vault password when prompted. This should display a warning about the password being less than 7 characters but still add it.

6. Verify Short Password Storage ✅
Confirm the short password was stored despite the warning:
# java -cp "bin:lib/*:." App --lookup-pass short
Enter your vault password when prompted. You should see the username and the short password.

7. Test Invalid Password Length Validation ✅
Test the validation for invalid password length:
# java -cp "bin:lib/*:." App --add --service invalid --user invaliduser --gen 0
This should fail with an error message and not add the password to the vault.

8. Add a Private Key Manually ✅
Now test the private key functionality by adding a key manually:
# java -cp "bin:lib/*:." App --add --service ssh --key "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtVJECJBVB"
Enter your vault password when prompted. The system should confirm the key was added.

9. Verify Manual Private Key Retrieval ✅
Confirm you can retrieve the manually added key:
# java -cp "bin:lib/*:." App --lookup-key ssh
Enter your vault password when prompted. You should see the private key you added.

10. Generate an ElGamal Key Pair ✅
Test the key generation functionality:
# java -cp "bin:lib/*:." App --add --service github --keygen
Enter your vault password when prompted. The system should generate a key pair, display the public key, and store the private key.

11. Verify Generated Private Key Retrieval ✅
Confirm you can retrieve the generated private key:
# java -cp "bin:lib/*:." App --lookup-key github
Enter your vault password when prompted. You should see the private key that was generated.

12. Test Error Handling for Non-Existent Entries ✅
Test how the system handles lookups for non-existent entries:
# java -cp "bin:lib/*:." App --lookup-pass nonexistent
Enter your vault password when prompted. The system should handle this gracefully with a "not found" message.
# java -cp "bin:lib/*:." App --lookup-key nonexistent
Enter your vault password when prompted. The system should handle this gracefully with a "not found" message.

