/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jckeystorage;

import applets.KeyStorageApplet;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Scanner;
import javacard.framework.ISOException;
import javax.smartcardio.CardException;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * The main class.
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class JCKeyStorage {
    
    private static class CommandLine {
        
        private static class ApplicationException extends Exception {

            public ApplicationException(String message) {
                super(message);
            }

            public ApplicationException(String message, Throwable cause) {
                super(message, cause);
            }
            
            public void printErrorAndExit() {
                System.err.println("ERROR: " + getMessage());
                Throwable cause = getCause();
                if (cause != null) {
                    if (cause instanceof ISOException) {
                        short sw = ((ISOException)cause).getReason();
                        System.err.printf("ERROR: ISO exception: %04x (%h)", sw, sw);
                        System.err.println();
                    } else {
                        System.err.println("ERROR: Exception: " + cause.toString());
                    }
                }
                System.exit(1);
            }
        }
        
        @Parameter(names = { "-?", "-h", "--help" }, help = true)
        private boolean help;

        @Parameter(
                names = { "-p", "--pubkey" },
                description = "the path to card's RSA public key",
                required = true)
        private String pubKeyPath;
        
        @Parameter(
                names = { "-t", "--terminal" },
                description = "the name of the card terminal to use")
        private String terminalName;
        
        private RSAKeyParameters readPublicKey() throws ApplicationException {
            try (FileInputStream file = new FileInputStream(pubKeyPath)) {
                ASN1StreamParser parser = new ASN1StreamParser(file);
                ASN1Primitive obj = parser.readObject().toASN1Primitive();
                if (!(obj instanceof ASN1Sequence)) {
                    throw new ApplicationException("Wrong public key file format!");
                }
                RSAPublicKey pk = RSAPublicKey.getInstance(obj);
                return new RSAKeyParameters(false, pk.getModulus(), pk.getPublicExponent());
            } catch(IOException ex) {
                throw new ApplicationException("Error reading the public key file!", ex);
            }
        }
        
        private void writePublicKey(RSAKeyParameters pubkey) throws ApplicationException {
            try (FileOutputStream file = new FileOutputStream(pubKeyPath)) {
                ASN1OutputStream out = new ASN1OutputStream(file);

                RSAPublicKey pk = new RSAPublicKey(pubkey.getModulus(), pubkey.getExponent());
                out.writeObject(pk);
            } catch(IOException ex) {
                throw new ApplicationException("Error writing the public key file!", ex);
            }
        }
        
        private static void clearPassword(char[] password) {
            Arrays.fill(password, '\0');
        }
        
        private static char[] readPassword() {
            return System.console().readPassword("Enter master password: ");
        }
        
        private static char[] readNewPassword() throws ApplicationException {
            char[] newPassword = System.console().readPassword("Enter new master password: ");
            char[] verPassword = System.console().readPassword("Verify new master password: ");
            if (!Arrays.equals(newPassword, verPassword)) {
                clearPassword(newPassword);
                clearPassword(verPassword);
                throw new ApplicationException("The passwords do not match!");
            }
            clearPassword(verPassword);
            return newPassword;
        }
        
        private static byte[] parseUuid(String uuidStr) throws ApplicationException {
            Scanner scanner = new Scanner(uuidStr);
            scanner.useDelimiter("-");
            byte[] res = new byte[40];
            try {
                for (int i = 0; i < 40; i++) {
                    res[i] = scanner.nextByte(16);
                }
            } catch(NoSuchElementException ex) {
                throw new ApplicationException("Invalid UUID!", ex);
            }
            if (scanner.hasNext()) {
                throw new ApplicationException("Invalid UUID!");
            }
            return res;
        }
        
        private interface Command {
            void run(KeyStorageClient client) throws ClientException, ApplicationException;
        }
        
        @Parameters(commandDescription = "Get the card's RSA authentication public key.")
        private class GetPubKeyCommand implements Command {

            @Override
            public void run(KeyStorageClient client) throws ClientException, ApplicationException {
                RSAKeyParameters pubkey;
                pubkey = client.getPublicKey();
                writePublicKey(pubkey);
            }
        }
        
        @Parameters(commandDescription = "Change the card's master password.")
        private class ChangePasswordCommand implements Command {

            @Override
            public void run(KeyStorageClient client) throws ClientException, ApplicationException {
                RSAKeyParameters cardKey = readPublicKey();
                KeyStorageClient.Session session = client.openSession(cardKey);
                try {
                    session.authenticate(readPassword());
                    session.changeMasterPassword(readNewPassword());
                } finally {
                    session.close();
                }
            }
        }

        @Parameters(commandDescription = "Generates the key using the card.")
        private class GenerateKeyCommand implements Command {
            @Parameter(names = "UUID", description = "the size of the key to generate", required = true)
            private int keySize;

            @Override
            public void run(KeyStorageClient client) throws ClientException, ApplicationException {
                if (keySize <= 0 || keySize > KeyStorageApplet.MAX_KEY_SIZE) {
                    throw new ApplicationException("Invalid key size (must be from 1 to " + KeyStorageApplet.MAX_KEY_SIZE + ")!");
                }
                RSAKeyParameters cardKey = readPublicKey();
                KeyStorageClient.Session session = client.openSession(cardKey);
                byte[] key = null;
                try {
                    session.authenticate(readPassword());
                    key = session.generateKey(keySize);
                    System.out.write(key, 0, keySize);
                } finally {
                    if (key != null) {
                        Arrays.fill(key, (byte)0);
                    }
                    session.close();
                }
            }
        }
        
        @Parameters(commandDescription = "Stores the key for a given partition.")
        private class StoreKeyCommand implements Command {
            @Parameter(names = "UUID", description = "the partition's UUID", required = true)
            private String uuidString;

            @Override
            public void run(KeyStorageClient client) throws ClientException, ApplicationException {
                byte[] uuid = parseUuid(uuidString);
                
                RSAKeyParameters cardKey = readPublicKey();
                KeyStorageClient.Session session = client.openSession(cardKey);
                byte[] key = new byte[KeyStorageApplet.MAX_KEY_SIZE];
                try {
                    int keySize = 0;
                    for (;;) {
                        int size = System.in.read(key, keySize, key.length - keySize);
                        if (size == 0) {
                            throw new ApplicationException("Key too long!");
                        }
                        if (size == -1) {
                            break;
                        }
                        keySize += size;
                    }
                    if (keySize == 0) {
                        throw new ApplicationException("Key too short!");
                    }
                    key = Arrays.copyOf(key, keySize);
                    session.storeKey(uuid, key);
                } catch (IOException ex) {
                    throw new ApplicationException("Error reading key!", ex);
                } finally {
                    Arrays.fill(key, (byte)0);
                    session.close();
                }
            }
        }
        
        @Parameters(commandDescription = "Loads the key for a given partition.")
        private class LoadKeyCommand implements Command {
            @Parameter(names = "UUID", description = "the partition's UUID", required = true)
            private String uuidString;

            @Override
            public void run(KeyStorageClient client) throws ClientException, ApplicationException {
                byte[] uuid = parseUuid(uuidString);
                
                RSAKeyParameters cardKey = readPublicKey();
                KeyStorageClient.Session session = client.openSession(cardKey);
                byte[] key = null;
                try {
                    key = session.loadKey(uuid);
                    System.out.write(key, 0, key.length);
                } finally {
                    if (key != null) {
                        Arrays.fill(key, (byte)0);
                    }
                    session.close();
                }
            }
        }
        
        @Parameters(commandDescription = "Deletes the key for a given partition.")
        private class DeleteKeyCommand implements Command {
            @Parameter(names = "UUID", description = "the partition's UUID", required = true)
            private String uuidString;

            @Override
            public void run(KeyStorageClient client) throws ClientException, ApplicationException {
                byte[] uuid = parseUuid(uuidString);
                
                RSAKeyParameters cardKey = readPublicKey();
                KeyStorageClient.Session session = client.openSession(cardKey);
                try {
                    session.deleteKey(uuid);
                } finally {
                    session.close();
                }
            }
        }
        
        private final GetPubKeyCommand getpubkey = new GetPubKeyCommand();
        private final ChangePasswordCommand changepw = new ChangePasswordCommand();
        private final GenerateKeyCommand genkey = new GenerateKeyCommand();
        private final StoreKeyCommand storekey = new StoreKeyCommand();
        private final LoadKeyCommand loadkey = new LoadKeyCommand();
        private final DeleteKeyCommand delkey = new DeleteKeyCommand();
        
        private CommandLine() { }
        
        private void run(JCommander jc) throws ApplicationException {
            JCommander jcCmd = jc.getCommands().get(jc.getParsedCommand());
            Command cmd = (Command)jcCmd.getObjects().get(0);
            
            RealSmartCardIO io;
            try {
                if (terminalName == null) {
                    io = RealSmartCardIO.openFirstTerminal();
                } else {
                    io = RealSmartCardIO.openTerminal(terminalName);
                }
            } catch(CardException ex) {
                throw new ApplicationException("Card error!", ex);
            }
            
            try {
                KeyStorageClient client = new KeyStorageClient(io, SecureRandom.getInstanceStrong());
                if (!client.selectApplet()) {
                    throw new ApplicationException("Unable to select applet!");
                }
                cmd.run(client);
            } catch(GeneralSecurityException | RuntimeCryptoException ex) {
                throw new ApplicationException("Crypto error!", ex);
            } catch (ClientException ex) {
                throw new ApplicationException("KeyStorageClient: " + ex.getMessage(), ex.getCause());
            }
        }
        
        public static void run(String[] args) {
            CommandLine cl = new CommandLine();
            JCommander jc = new JCommander(cl);
            jc.addCommand("getpubkey", cl.getpubkey);
            jc.addCommand("changepw", cl.changepw);
            jc.addCommand("genkey", cl.genkey);
            jc.addCommand("storekey", cl.storekey);
            jc.addCommand("loadkey", cl.loadkey);
            jc.addCommand("delkey", cl.delkey);
            jc.parse(args);
            
            if (cl.help) {
                jc.usage();
                return;
            }
            try {
                cl.run(jc);
            } catch(ApplicationException ex) {
                ex.printErrorAndExit();
            }
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        CommandLine.run(args);
    }
}
