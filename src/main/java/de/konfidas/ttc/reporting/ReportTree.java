//package de.konfidas.ttc.reporting;
//
//import java.util.ArrayList;
//import java.util.List;
//
///**
// * Generic Class for reporting. The class represents a tree structure of elements
// * that make up a report
// * @param <T> The type of the data to be reported
// */
//public class ReportTree<T> {
//    T data = null;
//    String name;
//    List<ReportTree<?>> children = new ArrayList<>();
//    ReportTree<?> parent = null;
//
//    public ReportTree(String name, T data) {
//        this.data = data;
//        this.name= name;
//    }
//
//    public ReportTree<?> addChild(ReportTree<?> child) {
//        child.setParent(this);
//        this.children.add(child);
//        return child;
//    }
//
//    public void addChildren(List<ReportTree<?>> children) {
//        children.forEach(each -> each.setParent(this));
//        this.children.addAll(children);
//    }
//
//    public List<ReportTree<?>> getChildren() {
//        return children;
//    }
//
//    public T getData() {
//        return data;
//    }
//
//    public void setData(T data) {
//        this.data = data;
//    }
//
//    public String getName() {
//        return name;
//    }
//
//    public void setName(String name) {
//        this.name = name;
//    }
//
//    void setParent(ReportTree<?> parent) {
//        this.parent = parent;
//    }
//
//    public ReportTree<?> getParent() {
//        return parent;
//    }
//
//
//}
