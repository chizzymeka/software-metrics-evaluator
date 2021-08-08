package classes;

import java.util.Objects;

public class CSVRow {

    private String methodSignature;
    private String className;
    private String confidenceLevel;
    private String age;
    private String codeChurn;
    private String cyclomaticComplexity;
    private String dependency;
    private String linesOfCode;
    private String version;
    private String sourceFilepath;
    private String line;

    public String getMethodSignature() {
        return methodSignature;
    }

    public void setMethodSignature(String methodSignature) {
        this.methodSignature = methodSignature;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String getConfidenceLevel() {
        return confidenceLevel;
    }

    public void setConfidenceLevel(String confidenceLevel) {
        this.confidenceLevel = confidenceLevel;
    }

    public String getAge() {
        return age;
    }

    public void setAge(String age) {
        this.age = age;
    }

    public String getCodeChurn() {
        return codeChurn;
    }

    public void setCodeChurn(String codeChurn) {
        this.codeChurn = codeChurn;
    }

    public String getCyclomaticComplexity() {
        return cyclomaticComplexity;
    }

    public void setCyclomaticComplexity(String cyclomaticComplexity) {
        this.cyclomaticComplexity = cyclomaticComplexity;
    }

    public String getDependency() {
        return dependency;
    }

    public void setDependency(String dependency) {
        this.dependency = dependency;
    }

    public String getLinesOfCode() {
        return linesOfCode;
    }

    public void setLinesOfCode(String linesOfCode) {
        this.linesOfCode = linesOfCode;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getSourceFilepath() {
        return sourceFilepath;
    }

    public void setSourceFilepath(String sourceFilepath) {
        this.sourceFilepath = sourceFilepath;
    }

    public String getLine() {
        return line;
    }

    public void setLine(String line) {
        this.line = line;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CSVRow csvRow = (CSVRow) o;
        return Objects.equals(methodSignature, csvRow.methodSignature) && Objects.equals(className, csvRow.className) && Objects.equals(confidenceLevel, csvRow.confidenceLevel) && Objects.equals(age, csvRow.age) && Objects.equals(codeChurn, csvRow.codeChurn) && Objects.equals(cyclomaticComplexity, csvRow.cyclomaticComplexity) && Objects.equals(dependency, csvRow.dependency) && Objects.equals(linesOfCode, csvRow.linesOfCode) && Objects.equals(version, csvRow.version) && Objects.equals(sourceFilepath, csvRow.sourceFilepath) && Objects.equals(line, csvRow.line);
    }

    @Override
    public int hashCode() {
        return Objects.hash(methodSignature, className, confidenceLevel, age, codeChurn, cyclomaticComplexity, dependency, linesOfCode, version, sourceFilepath, line);
    }

    @Override
    public String toString() {
        return "CSVRow{" +
                "methodSignature='" + methodSignature + '\'' +
                ", className='" + className + '\'' +
                ", confidenceLevel='" + confidenceLevel + '\'' +
                ", age='" + age + '\'' +
                ", codeChurn='" + codeChurn + '\'' +
                ", cyclomaticComplexity='" + cyclomaticComplexity + '\'' +
                ", dependency='" + dependency + '\'' +
                ", linesOfCode='" + linesOfCode + '\'' +
                ", version='" + version + '\'' +
                ", sourceFilepath='" + sourceFilepath + '\'' +
                ", line='" + line + '\'' +
                '}';
    }
}
