package de.konfidas.ttc.messages;

import de.konfidas.ttc.TTC;

import de.konfidas.ttc.exceptions.SystemLogParsingException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74 81 0A" +
                "   81 08" +
                "      01 02 03 04 05 06 07 08" +
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
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74 81 0A" +
                "   81 08" +
                "      01 02 03 04 05 06 07 08" +
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
        String hex = "30 35" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
                "   81 08" +
                "      01 02 03 04 05 06 07 08" +
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
        }catch(SystemLogParsingException e){
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
                "   04 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74 81 0A" +
                "   81 08" +
                "      01 02 03 04 05 06 07 08" +
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
        }catch(SystemLogParsingException e){
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
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74 81 0A" +
                "   04 08" +
                "      01 02 03 04 05 06 07 08" +
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
        }catch(SystemLogParsingException e){
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
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74 81 0A" +
                "   82 08" +
                "      01 02 03 04 05 06 07 08" +
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
        }catch(SystemLogParsingException e){
            // expected
        }
    }


    @Test
    public void parseMissingSystemOperationData() throws Exception {
        String hex = "30 3F" +
                "   02 01" +
                "      02" +
                "   06 09" +
                "      04 00 7F 00 07 03 07 01 02" +
                "   80 10" +
                "      64 65 72 65 67  69 73 74 65 72 43 6C 69 65 6E 74 81 0A" +
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
        }catch(SystemLogParsingException e){
            // expected
        }
    }


}
