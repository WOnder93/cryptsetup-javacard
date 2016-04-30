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
    
    public RealSmartCardIO(CardTerminal terminal) throws CardException {
        Card card = terminal.connect("*");
        card.getATR();
        channel = card.getBasicChannel();
    }
    
    public static RealSmartCardIO openTerminal(String terminalName) throws CardException {
        TerminalFactory factory = TerminalFactory.getDefault();
        CardTerminal terminal = factory.terminals().getTerminal(terminalName);
        return new RealSmartCardIO(terminal);
    }
    
    public static RealSmartCardIO openFirstTerminal() throws CardException {
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        CardTerminal terminal = terminals.get(0);
        return new RealSmartCardIO(terminal);
    }

    @Override
    public void installApplet(byte[] aidArray, Class appletClass, byte[] installData) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean selectApplet(byte[] aidArray) {
        ResponseAPDU res;
        try {
            res = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aidArray));
        } catch (CardException ex) {
            return false;
        }
        return (short)res.getSW() == ISO7816.SW_NO_ERROR;
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
