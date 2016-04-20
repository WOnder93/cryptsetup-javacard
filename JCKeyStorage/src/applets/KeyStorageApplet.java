/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package applets;

import javacard.framework.*;
import javacard.security.*;

/**
 * The applet for secure key storage on a smart card.
 * @author Manoja Kumar Das
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class KeyStorageApplet extends Applet {
    public static final byte[] AID = new byte[] {
        (byte)0x4a, (byte)0x43, (byte)0x4b, (byte)0x65, (byte)0x79, (byte)0x53,
        (byte)0x74, (byte)0x6f, (byte)0x72, (byte)0x61, (byte)0x67, (byte)0x65
    };
    
    public static final byte CLA_KEYSTORAGEAPPLET = (byte)0xB0;
    
    public static final byte INS_GETPUBKEY = (byte)0x50;
    public static final byte INS_HANDSHAKE = (byte)0x51;
    public static final byte INS_COMMAND   = (byte)0x52;
    
    public static final byte CMD_AUTH       = (byte)0x00;
    public static final byte CMD_CHANGEPW   = (byte)0x01;
    public static final byte CMD_GENKEY     = (byte)0x02;
    public static final byte CMD_STOREKEY   = (byte)0x03;
    public static final byte CMD_LOADKEY    = (byte)0x04;
    public static final byte CMD_DELKEY     = (byte)0x05;
    public static final byte CMD_CLOSE      = (byte)0x06;
    
    public static final short RSA_BITS = 2048;
    
    /* secp192r1, as per http://www.secg.org/sec2-v2.pdf */
    public static final byte[] EC_FP_P = new byte[] {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
    };
    public static final byte[] EC_FP_A = new byte[] {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC,
    };
    public static final byte[] EC_FP_B = new byte[] {
        (byte)0x64, (byte)0x21, (byte)0x05, (byte)0x19,
        (byte)0xE5, (byte)0x9C, (byte)0x80, (byte)0xE7,
        (byte)0x0F, (byte)0xA7, (byte)0xE9, (byte)0xAB,
        (byte)0x72, (byte)0x24, (byte)0x30, (byte)0x49,
        (byte)0xFE, (byte)0xB8, (byte)0xDE, (byte)0xEC,
        (byte)0xC1, (byte)0x46, (byte)0xB9, (byte)0xB1,
    };
    public static final byte[] EC_FP_G_x = new byte[] {
        (byte)0x18, (byte)0x8D, (byte)0xA8, (byte)0x0E,
        (byte)0xB0, (byte)0x30, (byte)0x90, (byte)0xF6,
        (byte)0x7C, (byte)0xBF, (byte)0x20, (byte)0xEB,
        (byte)0x43, (byte)0xA1, (byte)0x88, (byte)0x00,
        (byte)0xF4, (byte)0xFF, (byte)0x0A, (byte)0xFD,
        (byte)0x82, (byte)0xFF, (byte)0x10, (byte)0x12,
    };
    public static final byte[] EC_FP_G_y = new byte[] {
        (byte)0x07, (byte)0x19, (byte)0x2B, (byte)0x95,
        (byte)0xFF, (byte)0xC8, (byte)0xDA, (byte)0x78,
        (byte)0x63, (byte)0x10, (byte)0x11, (byte)0xED,
        (byte)0x6B, (byte)0x24, (byte)0xCD, (byte)0xD5,
        (byte)0x73, (byte)0xF9, (byte)0x77, (byte)0xA1,
        (byte)0x1E, (byte)0x79, (byte)0x48, (byte)0x11,
    };
    public static final byte[] EC_FP_R = new byte[] {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0x99, (byte)0xDE, (byte)0xF8, (byte)0x36,
        (byte)0x14, (byte)0x6B, (byte)0xC9, (byte)0xB1,
        (byte)0xB4, (byte)0xD2, (byte)0x28, (byte)0x31,
    };
    public static final short EC_FP_K = 1;
    
    private enum State {
        IDLE,
        KEY_ESTABILISHED,
        AUTHENTICATED,
    };
    
    public void process(APDU apdu) throws ISOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
