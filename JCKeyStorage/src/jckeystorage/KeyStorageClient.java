/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jckeystorage;

import applets.KeyStorageApplet;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * The client for interfacing with the applet.
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class KeyStorageClient {
    
    public static int EC_KEY_BITS = 128;
    
    private static ECParameterSpec getECParameters() throws GeneralSecurityException {
        ECFieldFp field = new ECFieldFp(new BigInteger(1, KeyStorageApplet.EC_FP_P));
        BigInteger a = new BigInteger(1, KeyStorageApplet.EC_FP_A);
        BigInteger b = new BigInteger(1, KeyStorageApplet.EC_FP_B);
        EllipticCurve curve = new EllipticCurve(field, a, b);

        BigInteger g_x = new BigInteger(1, KeyStorageApplet.EC_FP_G_x);
        BigInteger g_y = new BigInteger(1, KeyStorageApplet.EC_FP_G_y);
        ECPoint g = new ECPoint(g_x, g_y);

        BigInteger n = new BigInteger(1, KeyStorageApplet.EC_FP_R);

        return new ECParameterSpec(curve, g, n, KeyStorageApplet.EC_FP_K);
    }
    
    private final SmartCardIO io;
    
    private final KeyFactory rsaKeyFactory;
    private final ECParameterSpec ecParams;
    private final KeyFactory ecKeyFactory;
    private final KeyPairGenerator ecKeyGenerator;
    private final Signature rsaPkcs1Signature;
    private final KeyAgreement ecdh;
    private final Mac hmac256;
    private final Cipher aescbc; 
    
    public KeyStorageClient(SmartCardIO io) throws GeneralSecurityException {
        this.io = io;
        
        rsaKeyFactory = KeyFactory.getInstance("RSA");
        ecKeyFactory = KeyFactory.getInstance("EC");
        ecParams = getECParameters();
        ecKeyGenerator = KeyPairGenerator.getInstance("EC");
        ecKeyGenerator.initialize(ecParams);
        rsaPkcs1Signature = Signature.getInstance("SHA1withRSA");
        ecdh = KeyAgreement.getInstance("ECDH");
        hmac256 = Mac.getInstance("HmacSHA256");
        aescbc = Cipher.getInstance("AES/CBC/NoPadding");
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
    
    public RSAPublicKey getPublicKey() throws ClientException {
        byte[] data = sendInstruction(KeyStorageApplet.INS_GETPUBKEY).getData();
        if (data.length < 2) {
            throw new ClientException("Invalid response length!");
        }
        int modulusLengthOffset = 0;
        int modulusLength =
                (data[modulusLengthOffset] & 0xFF) |
                ((data[modulusLengthOffset + 1] & 0xFF) << 8);
        int modulusOffset = modulusLengthOffset + 2;
        if (data.length < modulusOffset + modulusLength + 2) {
            throw new ClientException("Invalid response length!");
        }
        BigInteger modulus = new BigInteger(Arrays.copyOfRange(data,
                modulusOffset, modulusOffset + modulusLength));
        
        int exponentLengthOffset = modulusOffset + modulusLength;
        int exponentLength =
                (data[exponentLengthOffset] & 0xFF) |
                ((data[exponentLengthOffset + 1] & 0xFF) << 8);
        int exponentOffset = exponentLengthOffset + 2;
        if (data.length < exponentOffset + exponentLength) {
            throw new ClientException("Invalid response length!");
        }
        BigInteger exponent = new BigInteger(Arrays.copyOfRange(data,
                exponentOffset, exponentOffset + exponentLength));
        
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        try {
            return (RSAPublicKey)rsaKeyFactory.generatePublic(spec);
        } catch (InvalidKeySpecException ex) {
            throw new ClientException("Invalid RSA public key!", ex);
        }
    }

    private class Session {
        private final SecretKeySpec encKey;
        private final SecretKeySpec authKey;
        
        private int seqNum = 0;
        
        public Session(byte[] encKey, byte[] authKey) {
            this.encKey = new SecretKeySpec(encKey, "AES");
            this.authKey = new SecretKeySpec(authKey, "HmacSHA256");
        }
        
        public byte[] wrapData(byte[] data) throws ClientException {
            int seqNumOffset = KeyStorageApplet.MAC_LENGTH;
            int ivOffset = seqNumOffset + KeyStorageApplet.SEQNUM_LENGTH;
            int dataOffset = ivOffset + KeyStorageApplet.IV_LENGTH;
            
            byte[] res = new byte[
                    KeyStorageApplet.MAC_LENGTH +
                    KeyStorageApplet.SEQNUM_LENGTH +
                    KeyStorageApplet.IV_LENGTH +
                    data.length];
            try {
                aescbc.init(Cipher.ENCRYPT_MODE, encKey);
                aescbc.doFinal(data, 0, data.length, res, dataOffset);
            } catch(GeneralSecurityException ex) {
                throw new ClientException("Encryption error!", ex);
            }
            
            System.arraycopy(aescbc.getIV(), 0, res, ivOffset, KeyStorageApplet.IV_LENGTH);
            res[seqNumOffset] = (byte)(seqNum & 0xFF);
            res[seqNumOffset + 1] = (byte)((seqNum >> 8) & 0xFF);
            
            seqNum++;
            
            try {
                hmac256.init(authKey);
                hmac256.update(res, seqNumOffset,
                        KeyStorageApplet.SEQNUM_LENGTH +
                        KeyStorageApplet.IV_LENGTH +
                        data.length);
                hmac256.doFinal(res, 0);
            } catch(GeneralSecurityException ex) {
                throw new ClientException("HMAC error!", ex);
            }
            return res;
        }

        public byte[] unwrapData(byte[] data) throws ClientException {
            int seqNumOffset = KeyStorageApplet.MAC_LENGTH;
            int ivOffset = seqNumOffset + KeyStorageApplet.SEQNUM_LENGTH;
            int dataOffset = ivOffset + KeyStorageApplet.IV_LENGTH;
            
            byte[] mac = new byte[KeyStorageApplet.MAC_LENGTH];
            try {
                hmac256.init(authKey);
                hmac256.update(data, seqNumOffset, data.length - seqNumOffset);
                hmac256.doFinal(mac, 0);
            } catch(GeneralSecurityException ex) {
                throw new ClientException("HMAC error!", ex);
            }
            if (!Arrays.equals(mac, Arrays.copyOf(data, KeyStorageApplet.MAC_LENGTH))) {
                throw new ClientException("Integrity check failed!");
            }

            int claimedSeqNum = (data[seqNumOffset] & 0xFF) | ((data[seqNumOffset + 1] & 0xFF) << 8);
            if (claimedSeqNum != seqNum) {
                throw new ClientException("Sequential number check failed!");
            }
            
            IvParameterSpec ivSpec = new IvParameterSpec(data, ivOffset, KeyStorageApplet.IV_LENGTH);
            try {
                aescbc.init(Cipher.ENCRYPT_MODE, encKey, ivSpec);
                return aescbc.doFinal(data, dataOffset, data.length - dataOffset);
            } catch(GeneralSecurityException ex) {
                throw new ClientException("Encryption error!", ex);
            } finally {
                seqNum++;
            }
        }
    }
    
    private static int getBytes(BigInteger x, byte[] dest, int offset, int bytes) {
        byte[] repr = x.toByteArray();
        System.arraycopy(repr, 0, dest, Math.max(bytes - repr.length, 0),
                Math.min(repr.length, bytes));
        return offset + bytes;
    }
    
    private static byte[] encodeECPoint(ECPoint pt, int bits) {
        int bytes = bits / 8 + (bits % 8 != 0 ? 1 : 0);
        BigInteger x = pt.getAffineX();
        BigInteger y = pt.getAffineY();
        byte[] res = new byte[1 + 2 * bytes];
        
        /* ANSI X9.62 encoding (uncompressed): */
        res[0] = (byte)0x04;
        int offset = 1;
        offset = getBytes(x, res, offset, bytes);
        getBytes(y, res, offset, bytes);
        return res;
    }
    
    private static ECPoint decodeECPoint(byte[] data, int offset, int length, int bits) throws ClientException {
        int bytes = bits / 8 + (bits % 8 != 0 ? 1 : 0);
        if (length < 1 + 2 * bytes) {
            throw new ClientException("Invalid response length!");
        }
        if (data[offset] != 0x04) {
            throw new ClientException("Invalid EC point format!");
        }
        offset += 1;
        
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(data, offset, bytes));
        offset += bytes;
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(data, offset, bytes));
        offset += bytes;
        return new ECPoint(x, y);
    }
    
    private boolean verifyCardSignature(RSAPublicKey cardKey, byte[] sigBytes, int sigOffset,
            byte[] dataBytes, int dataOffset) throws GeneralSecurityException
    {
        rsaPkcs1Signature.initVerify(cardKey);
        return rsaPkcs1Signature.verify(sigBytes, sigOffset, 20);
    }
    
    private Session openSession(RSAPublicKey cardKey) throws ClientException
    {
        KeyPair keyPair = ecKeyGenerator.generateKeyPair();
        ECPublicKey pub = (ECPublicKey)keyPair.getPublic();
        byte[] pubData = encodeECPoint(pub.getW(), KeyStorageApplet.EC_BITS);
        byte[] requestData = new byte[2 + pubData.length];
        if (pubData.length > Short.MAX_VALUE) {
            throw new ClientException("Handshake public data too large!");
        }
        requestData[0] = (byte)(pubData.length & 0xFF);
        requestData[1] = (byte)((pubData.length >> 8) & 0xFF);
        System.arraycopy(pubData, 0, requestData, 2, pubData.length);
        
        ResponseAPDU response = sendInstruction(KeyStorageApplet.INS_HANDSHAKE, requestData);
        byte[] res = response.getBytes();
        if (res.length < 2) {
            throw new ClientException("Invalid response length!");
        }
        int sigLength = (res[0] & 0xFF) | ((res[1] & 0xFF) << 8);
        
        int offset = 2;
        try {
            if (!verifyCardSignature(cardKey, res, offset, res, offset + sigLength)) {
                throw new ClientException("Invalid signature!");
            }
        } catch (GeneralSecurityException ex) {
            throw new ClientException("Signature verification error!", ex);
        }
        offset += sigLength;
        
        if (res.length - offset < requestData.length) {
            throw new ClientException("Invalid response length!");
        }
        if (!Arrays.equals(Arrays.copyOfRange(res, offset, requestData.length), requestData)) {
            throw new ClientException("Invalid response data!");
        }
        offset += requestData.length;
        
        if (res.length - offset < 2) {
            throw new ClientException("Invalid response length!");
        }
        int cardPubDataLength = (res[offset] & 0xFF) | ((res[offset + 1] & 0xFF) << 8);
        offset += 2;
        
        if (res.length - offset < cardPubDataLength) {
            throw new ClientException("Invalid response length!");
        }
        ECPoint cardPubPoint = decodeECPoint(res, offset, cardPubDataLength, KeyStorageApplet.EC_BITS);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(cardPubPoint, ecParams);
        try {
            ECPublicKey cardPub = (ECPublicKey)ecKeyFactory.generatePublic(keySpec);
            ecdh.init(keyPair.getPrivate());
            ecdh.doPhase(cardPub, true);
        } catch (GeneralSecurityException ex) {
            throw new ClientException("ECDH key exchange failed!", ex);
        }
        byte[] sessionMasterKey = ecdh.generateSecret();
        SecretKeySpec hmacKey = new SecretKeySpec(sessionMasterKey, "HmacSHA256");
        try {
            hmac256.init(hmacKey);
        } catch (InvalidKeyException ex) {
            throw new ClientException("Invalid HMAC key!", ex);
        }
        
        byte[] encKey = hmac256.doFinal(KeyStorageApplet.KEY_LABEL_ENC);
        byte[] authKey = hmac256.doFinal(KeyStorageApplet.KEY_LABEL_AUTH);
        return new Session(encKey, authKey);
    }
    
    private byte[] sendCommand(Session session, byte cmd, byte[] data) throws ClientException {
        int payloadSize = 1 + 2 + data.length;
        
        /* pad payload size to a multiple of AES block length: */
        int extra = payloadSize % KeyStorageApplet.BLOCK_LENGTH;
        if (extra != 0) {
            payloadSize += KeyStorageApplet.BLOCK_LENGTH - extra;
        }
        if (payloadSize > Short.MAX_VALUE) {
            throw new ClientException("Payload size too large!");
        }
        
        byte[] payload = new byte[payloadSize];
        payload[0] = cmd;
        payload[1] = (byte)(payloadSize & 0xFF);
        payload[2] = (byte)((payloadSize >> 8) & 0xFF);
        System.arraycopy(data, 0, payload, 3, data.length);

        ResponseAPDU apdu = sendInstruction(KeyStorageApplet.INS_COMMAND, session.wrapData(payload));
        byte[] res = session.unwrapData(apdu.getData());
        if (res.length < 2) {
            throw new ClientException("Invalid response length!");
        }
        int responseLength = (res[0] & 0xFF) | ((res[1] & 0xFF) << 8);
        if (res.length < 2 + responseLength) {
            throw new ClientException("Invalid response length!");
        }
        return Arrays.copyOfRange(res, 2, responseLength);
    }
    
    private void closeSession(Session session) {
        try {
            sendCommand(session, KeyStorageApplet.CMD_CLOSE, new byte[0]);
        } catch (ClientException ex) {
            /* ignore exception on closing */
        }
    }
    
    /* TODO... */
}
