/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jckeystorage;

import java.io.IOException;
import java.io.Writer;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class DumpingSmartCardIO implements SmartCardIO {
    
    private final SmartCardIO io;
    private final Writer out;
    
    public DumpingSmartCardIO(SmartCardIO io, Writer out) {
        this.io = io;
        this.out = out;
    }

    @Override
    public void installApplet(byte[] aidArray, Class appletClass, byte[] installData) {
        io.installApplet(aidArray, appletClass, installData);
    }

    @Override
    public boolean selectApplet(byte[] aidArray) {
        return io.selectApplet(aidArray);
    }

    @Override
    public ResponseAPDU transmitCommand(CommandAPDU command) {
        try {
            out.write(">> ");
            byte[] data = command.getBytes();
            for (int i = 0; i < data.length; i++) {
                out.write(String.format("%02x", data[i]));
            }
            out.write(System.lineSeparator());
        } catch (IOException ex) {
            /* whatever... */
        }
        ResponseAPDU res = io.transmitCommand(command);
        try {
            out.write("<< ");
            byte[] data = res.getBytes();
            for (int i = 0; i < data.length; i++) {
                out.write(String.format("%02x", data[i]));
            }
            out.write(System.lineSeparator());
        } catch (IOException ex) {
            /* whatever... */
        }
        return res;
    }
}
