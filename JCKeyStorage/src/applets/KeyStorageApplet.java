/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.*;
import javacardx.crypto.Cipher;

/**
 * The applet for secure key storage on a smart card.
 * @author Manoja Kumar Das
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class KeyStorageApplet extends Applet implements ExtendedLength {
    
    private static short readShort(byte[] buf, short offset) {
        /* read high byte: */
        short res = (short)(buf[(short)(offset + (short)1)] & (short)0xFF);
        res <<= (short)8;
        /* read low byte: */
        res |= (short)(buf[offset] & (short)0xFF);
        return res;
    }
    
    private static void writeShort(byte[] buf, short offset, short value) {
        buf[offset] = (byte)(value & (short)0xFF);
        ++offset;
        value >>= (short)8;
        buf[offset] = (byte)(value & (short)0xFF);
    }
    
    private static boolean arraysEqual(byte[] array1, short offset1, byte[] array2, short offset2, short length) {
        byte different = (byte)0x00;
        for (short i = 0; i < (short)length; i++) {
            different |= (byte)(array1[(short)(offset1 + i)] ^ array2[(short)(offset2 + i)]);
        }
        return different == (byte)0x00;
    }
    
    public static class HMAC {
        private final MessageDigest digest;
        private final short digestBlockSize;
        private final byte[] keyBuffer;
        
        public HMAC(MessageDigest digest, short digestBlockSize) {
            this.digest = digest;
            this.digestBlockSize = digestBlockSize;
            keyBuffer = new byte[(short)(2 * digestBlockSize)];
        }
        
        public final short getLength() {
            return digest.getLength();
        }
        
        private void xorBuffer(byte[] buffer, short offset, short length, byte xorKey) {
            short end = (short)(offset + length);
            while (offset < end) {
                buffer[offset] ^= xorKey;
                offset++;
            }
        }
        
        public final void setKey(byte[] buffer, short offset, short length) {
            short digestLength = digest.getLength();
            if (length <= digestBlockSize) {
                Util.arrayCopyNonAtomic(buffer, offset, keyBuffer, (short)0, length);
                Util.arrayFillNonAtomic(keyBuffer, length, (short)(digestBlockSize - length), (byte)0);
            } else {
                digest.doFinal(buffer, offset, length, keyBuffer, (short)0);
                Util.arrayFillNonAtomic(keyBuffer, digestLength, (short)(digestBlockSize - digestLength), (byte)0);
            }
            Util.arrayCopyNonAtomic(keyBuffer, (short)0, keyBuffer, digestBlockSize, digestBlockSize);
            
            xorBuffer(keyBuffer, (short)0, digestBlockSize, (byte)0x36);
            xorBuffer(keyBuffer, digestBlockSize, digestBlockSize, (byte)0x5C);
        }
        
        public final void clearKey() {
            Util.arrayFillNonAtomic(keyBuffer, (short)0, (short)keyBuffer.length, (byte)0);
        }
        
        public final void sign(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
            short digestLength = digest.getLength();
            digest.update(keyBuffer, (short)0, digestBlockSize);
            digest.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
            
            digest.update(keyBuffer, digestBlockSize, digestBlockSize);
            digest.doFinal(outBuffer, outOffset, digestLength, outBuffer, outOffset);
        }
    }
    
    public static class HMACVerifier {
        private final HMAC hmac;
        private final byte[] auxBuffer;

        public HMACVerifier(HMAC hmac) {
            this.hmac = hmac;
            auxBuffer = JCSystem.makeTransientByteArray(hmac.getLength(), JCSystem.CLEAR_ON_DESELECT);
        }

        public final boolean verify(byte[] inBuffer, short inOffset, short inLength, byte[] sigBuffer, short sigOffset) {
            hmac.sign(inBuffer, inOffset, inLength, auxBuffer, (short)0);
            try {
                return arraysEqual(sigBuffer, sigOffset, auxBuffer, (short)0, hmac.getLength());
            } finally {
                Util.arrayFillNonAtomic(auxBuffer, (short)0, (short)auxBuffer.length, (byte)0);
            }
        }
    }

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
    
    public static final short RSA_BITS = KeyBuilder.LENGTH_RSA_1024;
    public static final short EC_BITS = KeyBuilder.LENGTH_EC_FP_192;
    
    public static final short SESSION_KEY_LENGTH = 20;
    public static final byte[] KEY_LABEL_ENC = new byte[] { (byte)0xEE };
    public static final byte[] KEY_LABEL_AUTH = new byte[] { (byte)0xAA };
    
    public static final short MAC_LENGTH = 32;
    public static final short SEQNUM_LENGTH = 2;
    public static final short BLOCK_LENGTH = 16;
    public static final short IV_LENGTH = 16;
    
    public static final byte MAX_PW_TRIES = 5;
    public static final byte MAX_PW_LEN = 64;
    
    public static final short UUID_LENGTH = 40;
    public static final short MAX_KEY_SIZE = 128;
    public static final short KEY_ENTRY_SIZE = UUID_LENGTH + 1 + MAX_KEY_SIZE;
    
    public static final short MAX_KEY_ENTRIES = 64;
    
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
    public static final byte[] EC_FP_G_X = new byte[] {
        (byte)0x18, (byte)0x8D, (byte)0xA8, (byte)0x0E,
        (byte)0xB0, (byte)0x30, (byte)0x90, (byte)0xF6,
        (byte)0x7C, (byte)0xBF, (byte)0x20, (byte)0xEB,
        (byte)0x43, (byte)0xA1, (byte)0x88, (byte)0x00,
        (byte)0xF4, (byte)0xFF, (byte)0x0A, (byte)0xFD,
        (byte)0x82, (byte)0xFF, (byte)0x10, (byte)0x12,
    };
    public static final byte[] EC_FP_G_Y = new byte[] {
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
    
    private static final short STATE_IDLE = (short)0;
    private static final short STATE_KEY_ESTABILISHED = (short)1;
    private static final short STATE_AUTHENTICATED = (short)2;
    
    private static final short AUX_BUFFER_SIZE = 64;
    
    private short state;

    private final OwnerPIN masterPassword;
    
    private final KeyPair signingKeyPair;
    private final Signature signature;
    
    private final ECPublicKey dhPubKey;
    private final ECPrivateKey dhPrivKey;
    private final KeyPair dhKeyPair;
    private final KeyAgreement sessKeyAgreement;
    
    private final AESKey cipherKey;
    private final Cipher cipher;
    
    private final HMAC mac;
    private final HMACVerifier macVerifier;
    
    private final RandomData secureRandom;

    private short seqNum;
    
    private final byte[] keyStore;
    private final byte[] auxBuffer;
    
    private KeyStorageApplet(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        state = STATE_IDLE;
        auxBuffer = JCSystem.makeTransientByteArray(AUX_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        
        masterPassword = new OwnerPIN(MAX_PW_TRIES, MAX_PW_LEN);
        if (bLength == 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        } else {
            /* set master password from install data: */
            masterPassword.update(bArray, bOffset, bLength);
        }
        
        signingKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, RSA_BITS);
        signingKeyPair.genKeyPair();
        
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signature.init(signingKeyPair.getPrivate(), Signature.MODE_SIGN);
        
        dhPubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,  EC_BITS, false);
        dhPrivKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, EC_BITS, false);
        
        dhKeyPair = new KeyPair(dhPubKey, dhPrivKey);
        sessKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DHC, false);
        
        cipherKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_256, false);
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        
        mac = new HMAC(MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false), (short)64);
        macVerifier = new HMACVerifier(mac);
        
        secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        
        keyStore = new byte[(short)(MAX_KEY_ENTRIES * (short)(UUID_LENGTH + MAX_KEY_SIZE))];
    }
    
    private void setDHKeyParams() {
        /* prepare an ANSI X9.62 uncompressed EC point representation for G: */
        short gSize = (short)1;
        gSize += (short)EC_FP_G_X.length;
        gSize += (short)EC_FP_G_Y.length;
        auxBuffer[0] = 0x04;
        short off = 1;
        off = Util.arrayCopy(EC_FP_G_X, (short)0, auxBuffer, off, (short)EC_FP_G_X.length);
        Util.arrayCopy(EC_FP_G_Y, (short)0, auxBuffer, off, (short)EC_FP_G_Y.length);
        
        /* pre-set basic EC parameters: */
        dhPubKey.setFieldFP(EC_FP_P, (short)0, (short)EC_FP_P.length);
        dhPubKey.setA(EC_FP_A,   (short)0, (short)EC_FP_A.length);
        dhPubKey.setB(EC_FP_B,   (short)0, (short)EC_FP_B.length);
        dhPubKey.setG(auxBuffer, (short)0, gSize);
        dhPubKey.setR(EC_FP_R,   (short)0, (short)EC_FP_R.length);
        dhPubKey.setK(EC_FP_K);

        dhPrivKey.setFieldFP(EC_FP_P, (short)0, (short)EC_FP_P.length);
        dhPrivKey.setA(EC_FP_A,   (short)0, (short)EC_FP_A.length);
        dhPrivKey.setB(EC_FP_B,   (short)0, (short)EC_FP_B.length);
        dhPrivKey.setG(auxBuffer, (short)0, gSize);
        dhPrivKey.setR(EC_FP_R,   (short)0, (short)EC_FP_R.length);
        dhPrivKey.setK(EC_FP_K);
    }
    
    private void resetSession() {
        state = STATE_IDLE;
    }
    
    public final boolean select() {
        resetSession();
        return true;
    }
     
    /**
     * Method installing the applet.
     * @param bArray the array constaining installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        KeyStorageApplet applet = new KeyStorageApplet(bArray, bOffset, bLength);
        applet.register();
    }

    /**
     * Utility method to write the RSA public key into a buffer.
     * (Copied from HW02 solution)
     * @param buffer the output buffer
     * @param offset the output buffer offset
     * @return the size of the data written
     * @throws ISOException
     */
    private short fillPubKey(byte[] buffer, short offset) throws ISOException {
        short totalSize = 0;
        RSAPublicKey pubKey = (RSAPublicKey)signingKeyPair.getPublic();
        
        short modSizeOffset = offset;
        short modOffset = (short)(offset + (short)2);
        
        short modSize = pubKey.getModulus(buffer, modOffset);
        writeShort(buffer, modSizeOffset, modSize);
        totalSize += (short)2;
        totalSize += modSize;
        
        short expSizeOffset = (short)(modOffset + modSize);
        short expOffset = (short)(expSizeOffset + (short)2);
        
        short expSize = pubKey.getExponent(buffer, expOffset);
        writeShort(buffer, expSizeOffset, expSize);
        totalSize += (short)2;
        totalSize += expSize;
        
        return totalSize;
    }
    
    private short dhHandshake(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.getIncomingLength();
        
        short dataOffset = apdu.getOffsetCdata();
        
        short pubdataLen = readShort(apdubuf, dataOffset);
        short pubDataOffset = (short) (dataOffset + 2);
        
        dhKeyPair.genKeyPair();
        sessKeyAgreement.init(dhPrivKey);
        
        short sessKeyLen = sessKeyAgreement.generateSecret(
                apdubuf, pubDataOffset, pubdataLen,
                auxBuffer, (short)0);
        
        mac.setKey(auxBuffer, (short)0, sessKeyLen);
        
        mac.sign(KEY_LABEL_ENC, (short)0, (short)KEY_LABEL_ENC.length, auxBuffer, (short)0);
        cipherKey.setKey(auxBuffer, (short)0);
       
        mac.sign(KEY_LABEL_AUTH, (short)0, (short)KEY_LABEL_AUTH.length, auxBuffer, (short)0);
        mac.setKey(auxBuffer, (short)0, mac.getLength());

        short sigLength = signature.getLength();
        short sigLengthOffset = dataOffset;
        short sigOffset = (short)(sigLengthOffset + (short)2);
        
        short pdLengthOffset = (short)(sigOffset + sigLength);
        short pdOffset = (short)(pdLengthOffset + (short)2);
        
        Util.arrayCopy(apdubuf, dataOffset, apdubuf, pdLengthOffset, (short)((short)2 + pubdataLen));
        
        short cardpdLengthOffset = (short)(pdOffset + pubdataLen);
        short cardpdOffset = (short)(cardpdLengthOffset + (short)2);
        
        ECPublicKey pubKey = (ECPublicKey)dhKeyPair.getPublic();
        short cardpdLength = pubKey.getW(apdubuf, cardpdOffset);
        writeShort(apdubuf, cardpdLengthOffset, cardpdLength);
        
        short signedDataLength = (short)2;
        signedDataLength += pubdataLen;
        signedDataLength += (short)2;
        signedDataLength += cardpdLength;
        signature.sign(apdubuf, pdLengthOffset, signedDataLength, apdubuf, sigOffset);
        writeShort(apdubuf, sigLengthOffset, sigLength);
        
        seqNum = 0;
        state = STATE_KEY_ESTABILISHED;
        return (short)((short)(cardpdOffset - sigLengthOffset) + cardpdLength);
    }
    
    short InsCommand(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.getIncomingLength();

        short dataOffset = apdu.getOffsetCdata();
        short seqNumOffset = (short)(dataOffset + MAC_LENGTH);
        short ivOffset = (short)(seqNumOffset + SEQNUM_LENGTH);
        short payloadOffset = (short)(ivOffset + IV_LENGTH);
        
        short apduLen = (short)(dataOffset + dataLen);
        
	if (!macVerifier.verify(apdubuf, seqNumOffset, (short)(apduLen - seqNumOffset), apdubuf, dataOffset)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        
        short claimedSeqNum = readShort(apdubuf, seqNumOffset);
        if (claimedSeqNum != seqNum) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        
        cipher.init(cipherKey, Cipher.MODE_DECRYPT, apdubuf, ivOffset, BLOCK_LENGTH);        
        cipher.doFinal(
                apdubuf, payloadOffset, (short)(apduLen - payloadOffset),
                apdubuf, payloadOffset);
               
        short payloadLength = processCommand(apdubuf, payloadOffset);
        short extra = (short)(payloadLength % BLOCK_LENGTH);
        if (extra != (short)0) {
            payloadLength = (short)(payloadLength + (short)(BLOCK_LENGTH - extra));
        }
        
        secureRandom.generateData(apdubuf, ivOffset, BLOCK_LENGTH);
        
        cipher.init(cipherKey, Cipher.MODE_ENCRYPT, apdubuf, ivOffset, BLOCK_LENGTH);
        cipher.doFinal(apdubuf, payloadOffset, payloadLength, apdubuf, payloadOffset);
         
        writeShort(apdubuf, seqNumOffset, (short)(seqNum + 1));

        mac.sign(apdubuf, seqNumOffset, (short)(payloadLength + payloadOffset - seqNumOffset), apdubuf, dataOffset);
        
        seqNum = (short) (seqNum + 2) ;
        return (short)((short)(payloadOffset + payloadLength) - dataOffset);
    }

    public final void process(APDU apdu) throws ISOException {
        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        short dataLen = apdu.setIncomingAndReceive();
        byte[] apduBuffer = apdu.getBuffer();
        
        if (apduBuffer[ISO7816.OFFSET_CLA] != CLA_KEYSTORAGEAPPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        
        short size;
        switch(apduBuffer[ISO7816.OFFSET_INS]) {
            case INS_GETPUBKEY:
                // TODO: verify states
                size = fillPubKey(apduBuffer, apdu.getOffsetCdata());
                apdu.setOutgoingAndSend(apdu.getOffsetCdata(), size);
                break;
            case INS_HANDSHAKE:
                size = dhHandshake(apdu);
                apdu.setOutgoingAndSend(apdu.getOffsetCdata(), size);
                break;
            case INS_COMMAND:
                size = InsCommand(apdu);
                apdu.setOutgoingAndSend(apdu.getOffsetCdata(), size);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }
    
    private short commandAuth(byte[] buffer, short inOffset, short length, short outOffset) {
        if (state != STATE_KEY_ESTABILISHED) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        if (length > MAX_PW_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        if (masterPassword.check(buffer, inOffset, (byte)length) == false){
            state = STATE_IDLE;
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
            
        state = STATE_AUTHENTICATED;
        return 0;
    }

    private short commandChangePw(byte[] buffer, short inOffset, short length, short outOffset) {
        if (state != STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        if (length > MAX_PW_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        masterPassword.update(buffer, inOffset, (byte)length);
        return 0;
    }

    private short commandGenKey(byte[] buffer, short inOffset, short length, short outOffset) {
        if (state != STATE_AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        if (length != 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        byte keyLen = buffer[inOffset];
        if (keyLen <= 0 || keyLen > MAX_KEY_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        
        secureRandom.generateData(buffer, outOffset, keyLen);
        return keyLen;
    }
    
    private short findEmptyEntry() {
        for (short offset = 0; offset < keyStore.length; offset += KEY_ENTRY_SIZE) {
            if (keyStore[(short)(offset + UUID_LENGTH)] == 0) {
                return offset;
            }
        }
        return -1;
    }
    
    private void deleteEntry(short entryOffset) {
        short entryUuidOffset = entryOffset;
        short entryKeySizeOffset = (short)(entryUuidOffset + UUID_LENGTH);
        short entryKeyOffset = (short)(entryKeySizeOffset + 1);
        
        short keyLength = (short)(keyStore[entryKeySizeOffset] & 0xFF);
        
        keyStore[entryKeySizeOffset] = (byte)0x00;

        short end = (short)(entryKeyOffset + keyLength);
        while (entryKeyOffset < end) {
            keyStore[entryKeyOffset] = (byte)0x00;
            ++entryKeyOffset;
        }
    }
    
    private short readEntry(short entryOffset, byte[] key, short keyOffset) {
        short entryUuidOffset = entryOffset;
        short entryKeySizeOffset = (short)(entryUuidOffset + UUID_LENGTH);
        short entryKeyOffset = (short)(entryKeySizeOffset + 1);
        
        short keyLength = (short)(keyStore[entryKeySizeOffset] & 0xFF);
        Util.arrayCopy(keyStore, entryKeyOffset, key, keyOffset, keyLength);
        return keyLength;
    }
    
    private void writeEntry(short entryOffset,
            byte[] uuid, short uuidOffset,
            byte[] key, short keyOffset, short keyLength)
    {
        short entryUuidOffset = entryOffset;
        short entryKeySizeOffset = (short)(entryUuidOffset + UUID_LENGTH);
        short entryKeyOffset = (short)(entryKeySizeOffset + 1);
        Util.arrayCopy(uuid, uuidOffset, keyStore, entryUuidOffset, UUID_LENGTH);
        keyStore[entryKeySizeOffset] = (byte)(keyLength & 0xFF);
        Util.arrayCopy(key, keyOffset, keyStore, entryKeyOffset, keyLength);
    }
    
    private short findEntry(byte[] uuid, short uuidOffset) {
        for (short offset = 0; offset < keyStore.length; offset += KEY_ENTRY_SIZE) {
            if (keyStore[(short)(offset + UUID_LENGTH)] == 0) {
                continue;
            }
            if (arraysEqual(uuid, uuidOffset, keyStore, offset, UUID_LENGTH)) {
                return offset;
            }
        }
        return -1;
    }

    private short commandStoreKey(byte[] buffer, short inOffset, short length, short outOffset) {
        short keyLengthOffset = (short)(inOffset + UUID_LENGTH);
        short keyOffset = (short)(keyLengthOffset + 1);
        short keyLength = (short)(buffer[keyLengthOffset] & 0xff);
        if (keyLength <= 0 || keyLength > MAX_KEY_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        short entry = findEntry(buffer, inOffset);
        if (entry < 0) {
            entry = findEmptyEntry();
            if (entry < 0) {
                ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
            }
        }
        JCSystem.beginTransaction();
        writeEntry(entry, buffer, inOffset, buffer, keyOffset, keyLength);
        JCSystem.commitTransaction();
        return 0;
    }

    private short commandLoadKey(byte[] buffer, short inOffset, short length, short outOffset) {
        if (length != UUID_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        short entry = findEntry(buffer, inOffset);
        if (entry < 0) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        return readEntry(entry, buffer, outOffset);
    }

    private short commandDelKey(byte[] buffer, short inOffset, short length, short outOffset) {
        if (length != UUID_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        short entry = findEntry(buffer, inOffset);
        if (entry < 0) {
            ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
        }
        
        JCSystem.beginTransaction();
        deleteEntry(entry);
        JCSystem.commitTransaction();
        return 0;
    }

    private short commandClose(byte[] buffer, short inOffset, short length, short outOffset) {
        resetSession();
        return 0;
    }

    private short processCommand(byte[] buffer, short offset) {
        /* first byte is the command code; response data should be written
         * to the same buffer and its size returned */
        short inCmdOffset = offset;
        short inDataLengthOffset = (short)(offset + 1);
        short inDataOffset = (short)(inDataLengthOffset + 2);
        
        short outDataLengthOffset = offset;
        short outDataOffset = (short)(outDataLengthOffset + 2);
        
        byte command = buffer[inCmdOffset];
        short commandLen = readShort(buffer, inDataLengthOffset);
	switch(command) {
            case CMD_AUTH       : commandLen = commandAuth(buffer, inDataOffset, commandLen, outDataOffset); break;
            case CMD_CHANGEPW   : commandLen = commandChangePw(buffer, inDataOffset, commandLen, outDataOffset); break;
            case CMD_GENKEY     : commandLen = commandGenKey(buffer, inDataOffset, commandLen, outDataOffset); break;
            case CMD_STOREKEY   : commandLen = commandStoreKey(buffer, inDataOffset, commandLen, outDataOffset); break;
            case CMD_LOADKEY    : commandLen = commandLoadKey(buffer, inDataOffset, commandLen, outDataOffset); break;
            case CMD_DELKEY     : commandLen = commandDelKey(buffer, inDataOffset, commandLen, outDataOffset); break;
            case CMD_CLOSE      : commandLen = commandClose(buffer, inDataOffset, commandLen, outDataOffset); break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
        writeShort(buffer, outDataLengthOffset, commandLen);
        return (short)(2 + commandLen);
    }
}
