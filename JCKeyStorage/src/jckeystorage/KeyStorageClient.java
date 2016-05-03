/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jckeystorage;

import applets.KeyStorageApplet;
import java.math.BigInteger;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;

/**
 * The client for interfacing with the applet.
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class KeyStorageClient {
        
    private static final int MAX_RESPONSE_SIZE = 32767;
    
    private static ECDomainParameters getECParameters() {
        ECCurve curve = new SecP192R1Curve();
        
        BigInteger g_x = new BigInteger(1, KeyStorageApplet.EC_FP_G_X);
        BigInteger g_y = new BigInteger(1, KeyStorageApplet.EC_FP_G_Y);
        ECPoint g = curve.createPoint(g_x, g_y);
        
        BigInteger n = new BigInteger(1, KeyStorageApplet.EC_FP_R);
        return new ECDomainParameters(curve, g, n, BigInteger.valueOf(KeyStorageApplet.EC_FP_K));
    }
    
    private final SmartCardIO io;
    
    private final SecureRandom random;
    
    private final SHA1Digest sha1;
    private final SHA256Digest sha256;
    private final RSADigestSigner rsaSignature;
    private final ECDomainParameters ecParams;
    private final ECKeyPairGenerator ecKeyGenerator;
    private final ECDHCBasicAgreement ecdh;
    private final HMac hmac256;
    private final BlockCipher aesCbc; 
    
    public KeyStorageClient(SmartCardIO io, SecureRandom random) {
        this.io = io;
        this.random = random;
        
        sha1 = new SHA1Digest();
        sha256 = new SHA256Digest();
        ecParams = getECParameters();
        ecKeyGenerator = new ECKeyPairGenerator();
        ecKeyGenerator.init(new ECKeyGenerationParameters(ecParams, random));
        rsaSignature = new RSADigestSigner(sha1);
        ecdh = new ECDHCBasicAgreement();
        hmac256 = new HMac(sha256);
        aesCbc = new CBCBlockCipher(new AESEngine());
    }
    
    private static byte[] encodePassword(char[] password) {
        return Charset.forName("UTF-8").encode(CharBuffer.wrap(password)).array();
    }
    
    public final void installApplet(char[] masterPassword) {
        byte[] pwdBytes = encodePassword(masterPassword);
        try {
            io.installApplet(KeyStorageApplet.AID, KeyStorageApplet.class, pwdBytes);
        } finally {
            Arrays.fill(pwdBytes, (byte)0);
        }
    }
    
    public final boolean selectApplet() {
        return io.selectApplet(KeyStorageApplet.AID);
    }
    
    private static ResponseAPDU checkError(ResponseAPDU apdu) {
        short sw = (short)apdu.getSW();
        if (sw != ISO7816.SW_NO_ERROR) {
            ISOException.throwIt(sw);
        }
        return apdu;
    }
    
    private ResponseAPDU sendInstruction(int insCode) {
        CommandAPDU apdu = new CommandAPDU(KeyStorageApplet.CLA_KEYSTORAGEAPPLET,
                insCode, 0, 0, MAX_RESPONSE_SIZE);
        return checkError(io.transmitCommand(apdu));
    }
    
    private ResponseAPDU sendInstruction(int insCode, byte[] data) {
        CommandAPDU apdu = new CommandAPDU(KeyStorageApplet.CLA_KEYSTORAGEAPPLET,
                insCode, 0, 0, data, MAX_RESPONSE_SIZE);
        return checkError(io.transmitCommand(apdu));
    }
    
    private ResponseAPDU sendInstruction(int insCode, byte[] data, int offset, int length) {
        CommandAPDU apdu = new CommandAPDU(KeyStorageApplet.CLA_KEYSTORAGEAPPLET,
                insCode, 0, 0, data, offset, length, MAX_RESPONSE_SIZE);
        return checkError(io.transmitCommand(apdu));
    }
    
    public RSAKeyParameters getPublicKey() throws ClientException {
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
        BigInteger modulus = new BigInteger(1, Arrays.copyOfRange(data,
                modulusOffset, modulusOffset + modulusLength));
        
        int exponentLengthOffset = modulusOffset + modulusLength;
        int exponentLength =
                (data[exponentLengthOffset] & 0xFF) |
                ((data[exponentLengthOffset + 1] & 0xFF) << 8);
        int exponentOffset = exponentLengthOffset + 2;
        if (data.length < exponentOffset + exponentLength) {
            throw new ClientException("Invalid response length!");
        }
        BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(data,
                exponentOffset, exponentOffset + exponentLength));
        
        return new RSAKeyParameters(false, modulus, exponent);
    }

    private boolean verifyCardSignature(RSAKeyParameters cardKey,
            byte[] sigBytes, int sigOffset, int sigLength,
            byte[] dataBytes, int dataOffset, int dataLength)
    {
        rsaSignature.init(false, cardKey);
        rsaSignature.update(dataBytes, dataOffset, dataLength);
        return rsaSignature.verifySignature(Arrays.copyOfRange(sigBytes, sigOffset, sigOffset + sigLength));
    }
    
    public class Session {
        private final KeyParameter encKey;
        private final KeyParameter authKey;
        
        private int seqNum = 0;
        private boolean closed = false;
        private boolean authenticated = false;
        
        public Session(RSAKeyParameters cardKey) throws ClientException {
            AsymmetricCipherKeyPair keyPair = ecKeyGenerator.generateKeyPair();
            ECPublicKeyParameters pub = (ECPublicKeyParameters)keyPair.getPublic();
            byte[] pubData = pub.getQ().getEncoded(false);
            byte[] requestData = new byte[2 + pubData.length];
            if (pubData.length > Short.MAX_VALUE) {
                throw new ClientException("Handshake public data too large!");
            }
            requestData[0] = (byte)(pubData.length & 0xFF);
            requestData[1] = (byte)((pubData.length >> 8) & 0xFF);
            System.arraycopy(pubData, 0, requestData, 2, pubData.length);

            ResponseAPDU response = sendInstruction(KeyStorageApplet.INS_HANDSHAKE, requestData);
            byte[] res = response.getBytes();
            int resLength = response.getNr();
            if (resLength < 2) {
                throw new ClientException("Invalid response length!");
            }
            int sigLength = (res[0] & 0xFF) | ((res[1] & 0xFF) << 8);

            int offset = 2;
            if (!verifyCardSignature(cardKey,
                    res, offset, sigLength,
                    res, offset + sigLength, resLength - offset - sigLength)) {
                throw new ClientException("Invalid signature!");
            }
            offset += sigLength;

            if (resLength - offset < requestData.length) {
                throw new ClientException("Invalid response length!");
            }
            if (!Arrays.equals(Arrays.copyOfRange(res, offset, offset + requestData.length), requestData)) {
                throw new ClientException("Invalid response data!");
            }
            offset += requestData.length;

            if (resLength - offset < 2) {
                throw new ClientException("Invalid response length!");
            }
            int cardPubDataLength = (res[offset] & 0xFF) | ((res[offset + 1] & 0xFF) << 8);
            offset += 2;

            if (resLength - offset < cardPubDataLength) {
                throw new ClientException("Invalid response length!");
            }
            ECPoint cardPubPoint = ecParams.getCurve().decodePoint(Arrays.copyOfRange(res, offset, offset + cardPubDataLength));
            ECPublicKeyParameters cardPub = new ECPublicKeyParameters(cardPubPoint, ecParams);

            ecdh.init(keyPair.getPrivate());
            byte[] sharedSecret = ecdh.calculateAgreement(cardPub).toByteArray();

            byte[] sessionMasterKey = new byte[sha1.getDigestSize()];
            sha1.update(sharedSecret, 0, sharedSecret.length); 
            sha1.doFinal(sessionMasterKey, 0);
            KeyParameter hmacKey = new KeyParameter(sessionMasterKey);
            hmac256.init(hmacKey);

            byte[] encKey = new byte[hmac256.getMacSize()];
            hmac256.update(KeyStorageApplet.KEY_LABEL_ENC, 0, KeyStorageApplet.KEY_LABEL_ENC.length);
            hmac256.doFinal(encKey, 0);

            byte[] authKey = new byte[hmac256.getMacSize()];
            hmac256.update(KeyStorageApplet.KEY_LABEL_AUTH, 0, KeyStorageApplet.KEY_LABEL_AUTH.length);
            hmac256.doFinal(authKey, 0);

            this.encKey = new KeyParameter(encKey);
            this.authKey = new KeyParameter(authKey);
        }
        
        private byte[] wrapData(byte[] data) throws ClientException {
            int seqNumOffset = KeyStorageApplet.MAC_LENGTH;
            int ivOffset = seqNumOffset + KeyStorageApplet.SEQNUM_LENGTH;
            int dataOffset = ivOffset + KeyStorageApplet.IV_LENGTH;
            
            byte[] res = new byte[
                    KeyStorageApplet.MAC_LENGTH +
                    KeyStorageApplet.SEQNUM_LENGTH +
                    KeyStorageApplet.IV_LENGTH +
                    data.length];
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            
            aesCbc.init(true, new ParametersWithIV(encKey, iv));
            
            int blockSize = aesCbc.getBlockSize();
            for (int off = 0; off < data.length; off += blockSize) {
                aesCbc.processBlock(data, off, res, dataOffset + off);
            }
            
            System.arraycopy(iv, 0, res, ivOffset, KeyStorageApplet.IV_LENGTH);
            res[seqNumOffset] = (byte)(seqNum & 0xFF);
            res[seqNumOffset + 1] = (byte)((seqNum >> 8) & 0xFF);
            
            hmac256.init(authKey);
            hmac256.update(res, seqNumOffset,
                    KeyStorageApplet.SEQNUM_LENGTH +
                    KeyStorageApplet.IV_LENGTH +
                    data.length);
            hmac256.doFinal(res, 0);
            return res;
        }

        private byte[] unwrapData(byte[] data) throws ClientException {
            int seqNumOffset = KeyStorageApplet.MAC_LENGTH;
            int ivOffset = seqNumOffset + KeyStorageApplet.SEQNUM_LENGTH;
            int dataOffset = ivOffset + KeyStorageApplet.IV_LENGTH;
            
            byte[] mac = new byte[KeyStorageApplet.MAC_LENGTH];
            hmac256.init(authKey);
            hmac256.update(data, seqNumOffset, data.length - seqNumOffset);
            hmac256.doFinal(mac, 0);
            if (!Arrays.equals(mac, Arrays.copyOf(data, KeyStorageApplet.MAC_LENGTH))) {
                throw new ClientException("Integrity check failed!");
            }

            int claimedSeqNum = (data[seqNumOffset] & 0xFF) | ((data[seqNumOffset + 1] & 0xFF) << 8);
            if (claimedSeqNum != (seqNum + 1)) {
                throw new ClientException("Sequential number check failed!");
            }
            
            byte[] res = new byte[data.length - dataOffset];
            aesCbc.init(false, new ParametersWithIV(encKey, data, ivOffset, KeyStorageApplet.IV_LENGTH));
            
            int blockSize = aesCbc.getBlockSize();
            for (int off = 0; off < res.length; off += blockSize) {
                aesCbc.processBlock(data, dataOffset + off, res, off);
            }
            seqNum += 2;
            return res;
        }
        
        private byte[] sendCommand(byte cmd, byte[] data) throws ClientException {
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
            payload[1] = (byte)(data.length & 0xFF);
            payload[2] = (byte)((data.length >> 8) & 0xFF);
            System.arraycopy(data, 0, payload, 3, data.length);

            ResponseAPDU apdu = sendInstruction(KeyStorageApplet.INS_COMMAND, wrapData(payload));
            byte[] res = unwrapData(apdu.getData());
            if (res.length < 2) {
                throw new ClientException("Invalid response length!");
            }
            int responseLength = (res[0] & 0xFF) | ((res[1] & 0xFF) << 8);
            if (res.length < 2 + responseLength) {
                throw new ClientException("Invalid response length!");
            }
            return Arrays.copyOfRange(res, 2, 2 + responseLength);
        }

        private void checkAuthenticated() throws ClientException {
            if (!authenticated) {
                throw new IllegalStateException("Session not authenticated!");
            }
        }
        
        private void checkNotClosed() throws ClientException {
            if (closed) {
                throw new IllegalStateException("Session closed!");
            }
        }
        
        public void close() throws ClientException {
            checkNotClosed();
            
            try {
                sendCommand(KeyStorageApplet.CMD_CLOSE, new byte[0]);
            } catch (ClientException ex) {
                /* ignore exception on closing */
            } finally {
                closed = true;
            }
        }

        public void authenticate(char[] password) throws ClientException {
            checkNotClosed();
            
            byte[] encPassword = encodePassword(password);
            try {
                sendCommand(KeyStorageApplet.CMD_AUTH, encPassword);
            } catch (ISOException ex) {
                if (ex.getReason() == ISO7816.SW_WRONG_DATA) {
                    throw new ClientException("Invalid password!", ex);
                }
                throw ex;
            } finally {
                Arrays.fill(encPassword, (byte)0);
            }
            authenticated = true;
        }
    
        public void changeMasterPassword(char[] newPassword) throws ClientException {
            checkNotClosed();
            checkAuthenticated();
            
            byte[] encPassword = encodePassword(newPassword);
            try {
                sendCommand(KeyStorageApplet.CMD_CHANGEPW, encPassword);
            } finally {
                Arrays.fill(encPassword, (byte)0);
            }
        }
        
        public byte[] generateKey(int keyLength) throws ClientException {
            checkNotClosed();
            checkAuthenticated();
            
            if (keyLength <= 0) {
                throw new ClientException("Key size must be > 0!");
            }
            if (keyLength > Byte.MAX_VALUE) {
                throw new ClientException("Key size must be less than Byte.MAX_VALUE!");
            }
            
            return sendCommand(KeyStorageApplet.CMD_GENKEY, new byte[] { (byte)keyLength });
        }
        
        public void storeKey(byte[] uuid, byte[] key) throws ClientException {
            checkNotClosed();
            checkAuthenticated();
            
            if (uuid.length != 40) {
                throw new IllegalArgumentException("uuid");
            }
            
            if (key.length == 0) {
                throw new ClientException("Key size must be > 0!");
            }
            if (key.length > Byte.MAX_VALUE) {
                throw new ClientException("Key size must be less than Byte.MAX_VALUE!");
            }
            
            byte[] reqData = new byte[40 + 1 + key.length];
            System.arraycopy(uuid, 0, reqData, 0, 40);
            int offset = 40;
            reqData[offset++] = (byte)key.length;
            System.arraycopy(key, 0, reqData, offset, key.length);
            
            sendCommand(KeyStorageApplet.CMD_STOREKEY, reqData);
        }
        
        public byte[] loadKey(byte[] uuid) throws ClientException {
            checkNotClosed();
            checkAuthenticated();
            
            if (uuid.length != 40) {
                throw new IllegalArgumentException("uuid");
            }
            
            return sendCommand(KeyStorageApplet.CMD_LOADKEY, uuid);
        }
        
        public void deleteKey(byte[] uuid) throws ClientException {
            checkNotClosed();
            checkAuthenticated();
            
            if (uuid.length != 40) {
                throw new IllegalArgumentException("uuid");
            }
            
            sendCommand(KeyStorageApplet.CMD_DELKEY, uuid);
        }
    }
    
    public Session openSession(RSAKeyParameters cardKey) throws ClientException
    {
        return new Session(cardKey);
    }
}
