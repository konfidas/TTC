//package de.konfidas.ttc.reporting;
//
//import org.apache.commons.lang3.StringUtils;
//
//public class ReportTreeTextPrinter {
//
//    static public String printReportToText(ReportTree rep, Integer level) {
//        if (level==0){
//            level=1;
//        }
//        StringBuilder return_value = new StringBuilder();
//        return_value.append(rep.getName() +": ");
//        return_value.append(rep.getData().toString());
//        return_value.append( System.lineSeparator());
//
//        for(Object child : rep.getChildren()) {
//            return_value.append(StringUtils.repeat("    ", level));
//            return_value.append(ReportTreeTextPrinter.printReportToText((ReportTree)child,level+1));
//        }
//
//        return (return_value.toString());
//    }
//
//}
