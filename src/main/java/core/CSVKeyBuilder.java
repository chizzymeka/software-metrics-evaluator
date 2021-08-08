package core;

import au.com.bytecode.opencsv.CSVParser;
import au.com.bytecode.opencsv.CSVReader;
import classes.CSVRow;
import readers.CSVKeysAndConfidenceLevelFileReader;
import ucl.cdt.cybersecurity.App;
import utilities.CurrentTime;

import java.io.*;
import java.util.*;

public class CSVKeyBuilder {

    HashSet<String> predictedKeys = App.getPredictedKeys();
    HashSet<String> keysToSkip = App.getKeysToSkip();

    public void buildCSVRowObjects() throws IOException {

        System.out.println("Building objects from Software Metrics report rows...[" + new CurrentTime().getCurrentTimeStamp() + "]");

        boolean applyKeysToSkipFilter = App.isApplyKeysToSkipFilter();

        FileReader filereader = new FileReader("src/main/java/software-metrics-report/software_metrics_report_with_confidence_levels.csv");
        BufferedReader bufferedReader = new BufferedReader(filereader);
        CSVReader csvReader = new CSVReader(bufferedReader, CSVParser.DEFAULT_SEPARATOR, CSVParser.DEFAULT_QUOTE_CHARACTER, '\0', 0, CSVParser.DEFAULT_STRICT_QUOTES);

        String[] nextRecord;

        FileWriter fileWriter = new FileWriter("CSVKeysAndConfidenceLevel.txt");
        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);

        //-------------------- These keys are filtered out based on the same criteria applied in the Ground Truth Phase 5 ----------------------
        FileReader skippedMethodsNonWhollyAddedMethodsFileReader = new FileReader("skipped_methods_non_wholly_added_methods.txt");
        BufferedReader skippedMethodsNonWhollyAddedMethodsBufferedReader = new BufferedReader(skippedMethodsNonWhollyAddedMethodsFileReader);
        String skippedMethodsNonWhollyAddedMethodsLine;
        // read file line by line
        while ((skippedMethodsNonWhollyAddedMethodsLine = skippedMethodsNonWhollyAddedMethodsBufferedReader.readLine()) != null) {
            //System.out.println("Chizzy: " + skippedMethodsNonWhollyAddedMethodsLine);
            keysToSkip.add(skippedMethodsNonWhollyAddedMethodsLine.trim());
        }

        FileReader skippedMethodsTestDirectoriesMethodsFileReader = new FileReader("skipped_methods_test_directories_methods.txt");
        BufferedReader skippedMethodsTestDirectoriesMethodsBufferedReader = new BufferedReader(skippedMethodsTestDirectoriesMethodsFileReader);
        String skippedMethodsTestDirectoriesMethodsLine;
        // read file line by line
        while ((skippedMethodsTestDirectoriesMethodsLine = skippedMethodsTestDirectoriesMethodsBufferedReader.readLine()) != null) {
            //System.out.println("Meka: " + skippedMethodsTestDirectoriesMethodsLine);
            keysToSkip.add(skippedMethodsTestDirectoriesMethodsLine.trim());
        }
        //---------------------------------------------------------------------------------------------------------------------------------------

        String versionName = "";
        String filePath = "";
        String filepathSuffix = "";
        String className = "";
        String methodSignature = "";
        String confidenceLevel = "";

        int rowCounter = 0;
        while ((nextRecord = csvReader.readNext()) != null) {

            rowCounter++;

            if (rowCounter > 1) {

                //CSVRow csvRow = new CSVRow();

                for (int i = 0; i < nextRecord.length; i++) {
                    switch (i) {
                        case 0:
                            //csvRow.setMethodSignature(nextRecord[i]);
                            methodSignature = nextRecord[i].intern();
                            //System.out.println("methodSignature: " + methodSignature);
                            break;
                        case 1:
                            //csvRow.setClassName(nextRecord[i]);
                            className = nextRecord[i].intern();
                            //System.out.println("className: " + className);
                            break;
                        case 2:
                            //csvRow.setConfidenceLevel(nextRecord[i]);
                            confidenceLevel = nextRecord[i].intern();
                            //System.out.println("confidenceLevel: " + confidenceLevel);
                            break;
                        case 3:
                            //csvRow.setAge(nextRecord[i]);
                            break;
                        case 4:
                            //csvRow.setCodeChurn(nextRecord[i]);
                            break;
                        case 5:
                            //csvRow.setCyclomaticComplexity(nextRecord[i]);
                            break;
                        case 6:
                            //csvRow.setDependency(nextRecord[i]);
                            break;
                        case 7:
                            //csvRow.setLinesOfCode(nextRecord[i]);
                            break;
                        case 8:
                            //csvRow.setVersion(nextRecord[i]);
                            versionName = nextRecord[i].intern();
                            //System.out.println("versionName: " + versionName);
                            break;
                        case 9:

                            // Replace OpenCSV's default back slash with a forward slash to match up with the ground truth's JSON forward slash.
                            nextRecord[i] = nextRecord[i].replace("\\", "/");
                            //csvRow.setSourceFilepath(nextRecord[i]);
                            //------------------------------------------------------------------------------------------------------------------

                            filePath = nextRecord[i].intern();
                            filepathSuffix = filePath.split(versionName)[1].intern();
                            //System.out.println("filepathSuffix: " + filepathSuffix);
                            break;
                        case 10:
                            //csvRow.setLine(nextRecord[i]);
                            break;
                    }
                }

                String key = versionName + "=+=" + filepathSuffix + "=+=" + className + "=+=" + methodSignature.intern();

                if (applyKeysToSkipFilter) {
                    // Apply same ground truth-criteria filter and skip writing key if it is found in 'keysToSkip'.
                    if (!keysToSkip.contains(key)) {
                        bufferedWriter.write(key + "<-->" + confidenceLevel + "\n");
                    }
                } else {
                    bufferedWriter.write(key + "<-->" + confidenceLevel + "\n");
                }
            }
        }
        bufferedWriter.close();
        System.out.println("keysToSkip.size(): " + keysToSkip.size());
        keysToSkip.clear();
    }

    public void buildKeysForPredictedRows(int filterValue) throws IOException {

        System.out.println("Building keys for predicted rows...[" + new CurrentTime().getCurrentTimeStamp() + "]");

        HashMap<String, String> csvKeysAndConfidenceLevel = new CSVKeysAndConfidenceLevelFileReader().readCSVKeysAndConfidenceLevelFile();
        App.setAllCSVKeys(csvKeysAndConfidenceLevel.keySet());
        App.setCsvKeysAndConfidenceLevel(csvKeysAndConfidenceLevel);

        /*
            Set 'filter' variable to any of the options below:
            5 - VERY_HIGH
            4 - HIGH
            3 - MODERATE
            2 - LOW
            1 - VERY_LOW (Remember, it is pointless to filter by '1' as only levels 2 - 5 are outliers).
            0 - The last four confidence levels
         */

        int filter = filterValue;
        int floodGate = filter - 1;

        String[] confidenceLevelsArray = {"VERY_LOW", "LOW", "MODERATE", "HIGH", "VERY_HIGH"};
        ArrayList<String> confidenceLevelsList = new ArrayList<>();

        for (int i = filter; i > floodGate; i--) {

            if (filter == 0) {
                // This for loop skips 'VERY_LOW' level.
                for (int j = 1; j < confidenceLevelsArray.length; j++) {
                    confidenceLevelsList.add(confidenceLevelsArray[j]);
                }
            } else {
                confidenceLevelsList.add(confidenceLevelsArray[filter - 1]);
            }
        }

        System.out.println("Filtering by: " + confidenceLevelsList);

        FileWriter fileWriter = new FileWriter("predictedKeys.txt");

        for (Map.Entry<String, String> entry : csvKeysAndConfidenceLevel.entrySet()) {

            String key = entry.getKey();
            String confidenceLevel = entry.getValue();

            if (confidenceLevelsList.contains(confidenceLevel)) {
                predictedKeys.add(key);
                fileWriter.write(key + "\n");
            }
        }
        fileWriter.close();
    }
}
