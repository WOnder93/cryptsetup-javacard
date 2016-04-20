package jckeystorage;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * An interface abstracting the SmartCard IO API (simulator vs. the real thing)..
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public interface SmartCardIO {
    
    void installApplet(byte[] aidArray, Class appletClass, byte[] installData);
    boolean selectApplet(byte[] aidArray);
    ResponseAPDU transmitCommand(CommandAPDU command);
}
