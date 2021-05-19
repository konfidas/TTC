package de.konfidas.ttc.reporting;

import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Primitive;

public class ReportTextPrinter {

    static public String printReportToText(Report rep, Integer level) {
        if (level==0){
            level=1;
        }
        StringBuilder return_value = new StringBuilder();
        return_value.append(rep.getName() +": ");
        return_value.append(rep.getData().toString());
        return_value.append( System.lineSeparator());

        for(Object child : rep.getChildren()) {
            return_value.append(StringUtils.repeat("    ", level));
            return_value.append(ReportTextPrinter.printReportToText((Report)child,level+1));
        }

        return (return_value.toString());
    }

}
