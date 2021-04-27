package de.konfidas.ttc.messages;


public class StartTransactionLogMessageBuilder extends TransactionLogMessageBuilder{

 public StartTransactionLogMessageBuilder(){
     operationType = "StartTransaction";
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
        filename += (transactionNumber == null) ? "_Log_No-_Start" : "_Log_No-" +transactionNumber+ "_Start";
        filename += (clientID == null) ? ".log" : clientID+".log";
        return filename;
    }


}
