package jckeystorage;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.util.Properties;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * The JCardSim implementation of {@code SmartCardIO}.
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class SimulatorSmartCardIO implements SmartCardIO {

    private final JavaxSmartCardInterface simulator;
    
    private SimulatorSmartCardIO() {
        Properties props = new Properties(System.getProperties());
        props.setProperty("com.licel.jcardsim.terminal.type", "2");
        CAD cad = new CAD(props);
        simulator = (JavaxSmartCardInterface)cad.getCardInterface();
    }
    
    public static final SimulatorSmartCardIO INSTANCE = new SimulatorSmartCardIO();

    @Override
    public void installApplet(byte[] aidArray, Class appletClass, byte[] installData) {
        AID aid = new AID(aidArray, (short) 0, (byte) aidArray.length);
        simulator.installApplet(aid, appletClass, installData, (short) 0, (byte) installData.length);
    }

    @Override
    public boolean selectApplet(byte[] aidArray) {
        AID aid = new AID(aidArray, (short) 0, (byte) aidArray.length);
        return simulator.selectApplet(aid);
    }

    @Override
    public ResponseAPDU transmitCommand(CommandAPDU apdu) {
        return simulator.transmitCommand(apdu);
    }
}
