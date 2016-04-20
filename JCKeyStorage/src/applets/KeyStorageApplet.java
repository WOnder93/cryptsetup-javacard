/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package applets;

import javacard.framework.*;
import javacard.security.*;

/**
 *
 * @author ondrej
 */
public class KeyStorageApplet extends Applet {
    public static final byte[] AID = new byte[] {
        (byte)0x4a, (byte)0x43, (byte)0x4b, (byte)0x65, (byte)0x79, (byte)0x53,
        (byte)0x74, (byte)0x6f, (byte)0x72, (byte)0x61, (byte)0x67, (byte)0x65
    };
    
    public static final byte CLA_KEYSTORAGEAPPLET = (byte)0xB0;
    
    public void process(APDU apdu) throws ISOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
