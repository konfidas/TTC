package de.konfidas.ttc.messages;


public class UpdateTransactionLogMessageBuilder extends TransactionLogMessageBuilder{

    public UpdateTransactionLogMessageBuilder(){
        operationType = "UpdateTransaction";
    }

    @Override
    String constructFileName() {
        switch (logTimeType) {
            case "unixTime":
                filename = "Unixt_" + logTimeUnixTime + "_Sig-";
                break;
            case "utcTime":
                filename = "UTCTime_" + logTimeUTC + "_Sig-";
                break;
            case "generalizedTime":
                filename = "Gent_" + logTimeGeneralizedTime + "_Sig-";
                break;
        }

        filename = filename + signatureCounter.toString();
        filename += (transactionNumber == null) ? "_Log_No-_Update" : "_Log_No-" +transactionNumber+ "_Update";
        filename += (clientID == null) ? ".log" : clientID+".log";
        return filename;
    }


}
