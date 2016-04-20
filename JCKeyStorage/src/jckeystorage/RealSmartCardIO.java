/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jckeystorage;

import java.util.List;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/**
 * The implementation of {@code SmartCardIO} for communicating with a real card.
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public final class RealSmartCardIO implements SmartCardIO {
    
    CardChannel channel;
    
    public RealSmartCardIO() throws CardException {
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        CardTerminal terminal = terminals.get(0);
        Card card = terminal.connect("*");
        channel = card.getBasicChannel();
    }

    @Override
    public void installApplet(byte[] aidArray, Class appletClass, byte[] installData) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean selectApplet(byte[] aidArray) {
        try {
            channel.transmit(new CommandAPDU(
                    ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 0, 0, aidArray));
        } catch (ISOException | CardException ex) {
            return false;
        }
        return true;
    }

    @Override
    public ResponseAPDU transmitCommand(CommandAPDU command) {
        try {
            return channel.transmit(command);
        } catch (CardException ex) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
            return null;
        }
    }
    
}
