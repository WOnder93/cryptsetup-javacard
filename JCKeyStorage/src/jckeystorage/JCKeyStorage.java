/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jckeystorage;

import java.security.GeneralSecurityException;

/**
 * The main class.
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class JCKeyStorage {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
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
        //System.out.println(client.getPublicKey());
        
        //client.sendCommand((byte)0, null);
    }
    
}
