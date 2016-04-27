/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jckeystorage;

import java.security.GeneralSecurityException;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * The main class.
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class JCKeyStorage {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws ClientException {
        KeyStorageClient client;
        try {
            client = new KeyStorageClient(SimulatorSmartCardIO.INSTANCE);
        } catch (GeneralSecurityException ex) {
            System.err.printf("ERROR: Unable to initialize JC client: %s", ex);
            System.exit(1);
            return;
        }
        client.installApplet("test");
        client.selectApplet();
        
        RSAKeyParameters publicKey = client.getPublicKey();
        KeyStorageClient.Session session = client.openSession(publicKey);
        session.authenticate("test");
        session.close();
    }
    
}
