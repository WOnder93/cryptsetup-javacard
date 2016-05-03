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
        
        byte[] data = new byte[1 + aidArray.length + 1 + 0 + 1 + installData.length];
        int offset = 0;
        data[offset++] = (byte)aidArray.length;
        System.arraycopy(aidArray, 0, data, offset, aidArray.length);
        offset += aidArray.length;
        data[offset++] = (byte)0;
        data[offset++] = (byte)installData.length;
        System.arraycopy(installData, 0, data, offset, installData.length);
        
        simulator.installApplet(aid, appletClass, data, (short)0, (byte)data.length);
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
