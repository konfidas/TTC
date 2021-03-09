package de.konfidas.ttc.messages;

import de.konfidas.ttc.TTC;

import de.konfidas.ttc.exceptions.SystemLogParsingException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

public class TestParseSystemLog {
    final static Logger logger = LoggerFactory.getLogger(TTC.class);

    @Test
    public void parseNoAdditionalInputData() throws Exception {
        String hex = "30 49" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
// Operation Type:
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74" +
// System Operation Data:
                "   81 0A" +
                "      00 01 02 03 04 05 06 07 08 09" +
// No Additional Input
                "   04 01" +
                "      FF" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);
        SystemLogMessage msg = new SystemLogMessage(systemLog, "");
    }

    @Test
    public void parseWithAdditionalInputData() throws Exception {
        String hex = "30 4D" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74" +
                "   81 0A" +
                "      00 01 02 03 04 05 06 07 08 09" +
// Additional Input:
                "   82 02" +
                "      01 02" +
                "   04 01" +
                "      FF" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                        .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);
        SystemLogMessage msg = new SystemLogMessage(systemLog, "");
    }


    @Test
    public void parseMissingOperationData() throws Exception {
        String hex = "30 37" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
// Missing Operation Data:
//                "   80 10" +
//               "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74" +
                "   81 0A" +
                "      00 01 02 03 04 05 06 07 08 09" +
                "   04 01" +
                "      FF" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                        .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);
        try {
            SystemLogMessage msg = new SystemLogMessage(systemLog, "");
            fail();
        }catch(SystemLogMessage.OperationTypeParsingException e){
            // expected!
        }
    }

    @Test
    public void parseOperationDataWrongTag() throws Exception {
        String hex = "30 49" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
// Wrong Tag:
                "   04 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74 " +
                "   81 0A" +
                "      00 01 02 03 04 05 06 07 08 09" +
                "   04 01" +
                "      FF" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                        .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);
        try {
            SystemLogMessage msg = new SystemLogMessage(systemLog, "");
            fail();
        }catch(SystemLogMessage.OperationTypeParsingException e){
            // expected
        }
    }

    @Test
    public void parseSystemOperationDataWrongTag() throws Exception {
        String hex = "30 49" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74 " +
// Wrong Tag:
                "   04 0A" +
                "      00 01 02 03 04 05 06 07 08 09" +
                "   04 01" +
                "      FF" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                        .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);
        try {
            SystemLogMessage msg = new SystemLogMessage(systemLog, "");
            fail();
        }catch(SystemLogMessage.SystemOperationDataParsingException e){
            // expected
        }
    }

    @Test
    public void parseMissingSystemOperationDataWithAdditionalInputData() throws Exception {
        String hex = "30 49" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74" +
// Missing System Operation Data:
//                "   81 0A" +
//                "      00 01 02 03 04 05 06 07 08 09" +
// Additional Input:
                "   82 0A" +
                "      00 01 02 03 04 05 06 07 08 09" +
                "   04 01" +
                "      FF" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                        .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);
        try {
            SystemLogMessage msg = new SystemLogMessage(systemLog, "");
            fail();
        }catch(SystemLogMessage.SystemOperationDataParsingException e){
            // expected
        }
    }


    @Test
    public void parseMissingSystemOperationData() throws Exception {
        String hex = "30 3D" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74" +
// Missing SystemOperationData:
//                "   81 0A" +
//               "       00 01 02 03 04 05 06 07 08 09" +
                "   04 01" +
                "      FF" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                        .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);
        try {
            SystemLogMessage msg = new SystemLogMessage(systemLog, "");
            fail();
        }catch(SystemLogMessage.SystemOperationDataParsingException e){
            // expected
        }
    }

    @Test
    public void parseWrongOid1() throws Exception {
        String hex = "30 49" +
                "   02 01" +
                "      02" +
                "   06 09" +
// Wrong OID:
                "      04 00 7F 00 07 03 07 01 01" +
// Operation Type:
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74" +
// System Operation Data:
                "   81 0A" +
                "      00 01 02 03 04 05 06 07 08 09" +
// No Additional Input
                "   04 01" +
                "      FF" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                        .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);
        try {
            SystemLogMessage msg = new SystemLogMessage(systemLog, "");
            fail();
        }catch(LogMessage.CertifiedDataTypeParsingException e){
            // expected
        }
    }

    @Test
    public void parseWrongOid2() throws Exception {
        String hex = "30 49" +
                "   02 01" +
                "      02" +
                "   06 09" +
// Wrong OID:
                "      04 00 7F 00 07 03 07 01 03" +
// Operation Type:
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74" +
// System Operation Data:
                "   81 0A" +
                "      00 01 02 03 04 05 06 07 08 09" +
// No Additional Input
                "   04 01" +
                "      FF" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                        .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);
        try {
            SystemLogMessage msg = new SystemLogMessage(systemLog, "");
            fail();
        }catch(LogMessage.CertifiedDataTypeParsingException e){
            // expected
        }
    }


    @Test
    public void checkSerialNumber() throws Exception {
        String hex = "30 4E" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74" +
                "   81 0A" +
                "      00 01 02 03 04 05 06 07 08 09" +
// Serial Number:
                "   04 06" +
                "      FF 00 11 22 33 44" +
                "   30 0C" +
                "      06 0A" +
                "         04 00 7F  00 07 01 01 04 01 04 02 01 17" +
                "   02 04" +
                "      5F CE 6A 88" +
                "   04 01" +
                "      FF"

                        .replace("\\\\s+","");
        byte[] systemLog = Hex.decode(hex);

        byte[] expectedSerialNumber = Hex.decode("FF 00 11 22 33 44");

        SystemLogMessage msg = new SystemLogMessage(systemLog, "");

        assertArrayEquals(msg.getSerialNumber(), expectedSerialNumber);
    }

}
