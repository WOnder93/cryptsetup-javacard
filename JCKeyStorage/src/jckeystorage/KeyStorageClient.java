/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jckeystorage;

import applets.KeyStorageApplet;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * The client for interfacing with the applet.
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class KeyStorageClient {
    
    public static int EC_KEY_BITS = 128;
    
    private static KeyFactory rsaKeyFactory = null;
    private static KeyPairGenerator ecKeyGenerator = null;
    
    private static KeyFactory getRsaKeyFactory() throws NoSuchAlgorithmException {
        if (rsaKeyFactory == null) {
            rsaKeyFactory = KeyFactory.getInstance("RSA");
        }
        return rsaKeyFactory;
    }
    
    private static KeyPairGenerator getECKeyGenerator() throws NoSuchAlgorithmException {
        if (ecKeyGenerator == null) {
            ecKeyGenerator = KeyPairGenerator.getInstance("EC");
            
            ECFieldFp field = new ECFieldFp(new BigInteger(1, KeyStorageApplet.EC_FP_P));
            BigInteger a = new BigInteger(1, KeyStorageApplet.EC_FP_A);
            BigInteger b = new BigInteger(1, KeyStorageApplet.EC_FP_B);
            EllipticCurve curve = new EllipticCurve(field, a, b);

            BigInteger g_x = new BigInteger(1, KeyStorageApplet.EC_FP_G_x);
            BigInteger g_y = new BigInteger(1, KeyStorageApplet.EC_FP_G_x);
            ECPoint g = new ECPoint(g_x, g_y);

            BigInteger n = new BigInteger(1, KeyStorageApplet.EC_FP_R);

            ECParameterSpec spec = new ECParameterSpec(curve, g, n, KeyStorageApplet.EC_FP_K);
            try {
                ecKeyGenerator.initialize(spec);
            } catch (InvalidAlgorithmParameterException ex) {
                /* if this happens, it's the programmer's fault */
                throw new AssertionError("FATAL: Wrong EC parameters specified!");
            }
        }
        return ecKeyGenerator;
    }
    
    private final SmartCardIO io;
    
    public KeyStorageClient(SmartCardIO io) {
        this.io = io;
    }
    
    public final void installApplet(String masterPassword) {
        byte[] pwdBytes = Charset.forName("UTF-8").encode(masterPassword).array();
        io.installApplet(KeyStorageApplet.AID, KeyStorageApplet.class, pwdBytes);
    }
    
    public final boolean selectApplet() {
        return io.selectApplet(KeyStorageApplet.AID);
    }
    
    private ResponseAPDU checkError(ResponseAPDU apdu) {
        short sw = (short)apdu.getSW();
        if (sw != ISO7816.SW_NO_ERROR) {
            ISOException.throwIt(sw);
        }
        return apdu;
    }
    
    private ResponseAPDU sendInstruction(int insCode) {
        CommandAPDU apdu = new CommandAPDU(KeyStorageApplet.CLA_KEYSTORAGEAPPLET,
                insCode, 0, 0);
        return checkError(io.transmitCommand(apdu));
    }
    
    private ResponseAPDU sendInstruction(int insCode, byte[] data) {
        CommandAPDU apdu = new CommandAPDU(KeyStorageApplet.CLA_KEYSTORAGEAPPLET,
                insCode, 0, 0, data);
        return checkError(io.transmitCommand(apdu));
    }
    
    private ResponseAPDU sendInstruction(int insCode, byte[] data, int offset, int length) {
        CommandAPDU apdu = new CommandAPDU(KeyStorageApplet.CLA_KEYSTORAGEAPPLET,
                insCode, 0, 0, data, offset, length);
        return checkError(io.transmitCommand(apdu));
    }
    
    public PublicKey getPublicKey() {
        byte[] data = sendInstruction(KeyStorageApplet.INS_GETPUBKEY).getData();
        if (data.length < 2) {
            return null;
        }
        int modulusLengthOffset = 0;
        int modulusLength =
                (data[modulusLengthOffset] & 0xFF) |
                ((data[modulusLengthOffset + 1] & 0xFF) << 8);
        int modulusOffset = modulusLengthOffset + 2;
        if (data.length < modulusOffset + modulusLength + 2) {
            return null;
        }
        BigInteger modulus = new BigInteger(Arrays.copyOfRange(data,
                modulusOffset, modulusOffset + modulusLength));
        
        int exponentLengthOffset = modulusOffset + modulusLength;
        int exponentLength =
                (data[exponentLengthOffset] & 0xFF) |
                ((data[exponentLengthOffset + 1] & 0xFF) << 8);
        int exponentOffset = exponentLengthOffset + 2;
        if (data.length < exponentOffset + exponentLength) {
            return null;
        }
        BigInteger exponent = new BigInteger(Arrays.copyOfRange(data,
                exponentOffset, exponentOffset + exponentLength));
        
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        try {
            return getRsaKeyFactory().generatePublic(spec);
        } catch(NoSuchAlgorithmException | InvalidKeySpecException ex) {
            return null;
        }
    }
    
    private byte[] sendCommand(byte cmd, byte[] data) {
        //getECKeyGenerator().
        //ResponseAPDU response = sendInstruction(KeyStorageApplet.INS_HANDSHAKE, data);
        // TODO
        return null;
    }
}
