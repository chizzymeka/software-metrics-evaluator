package ucl.cdt.cybersecurity;

import core.CSVKeyBuilder;
import core.Evaluator;
import core.JSONKeyBuilder;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;


public class App {

    private static Set<String> allCSVKeys = new HashSet<>();
    private static HashSet<String> predictedKeys = new HashSet<>();
    private static HashSet<String> groundTruthJSONDataKeys = new HashSet<>();
    private static HashMap<String, String> csvKeysAndConfidenceLevel = new HashMap<>();
    private static HashSet<String> keysToSkip = new HashSet<>();
    private static boolean applyKeysToSkipFilter = false;

    public static void main( String[] args ) throws IOException {

        File CSVKeysAndConfidenceLevelFile = new File("CSVKeysAndConfidenceLevel.txt");

        if (!CSVKeysAndConfidenceLevelFile.exists()) {
        }
        new CSVKeyBuilder().buildCSVRowObjects();

        /*
            Set 'filter' variable to any of the options below:
            5 - VERY_HIGH
            4 - HIGH
            3 - MODERATE
            2 - LOW
            1 - VERY_LOW (Remember, it is pointless to filter by '1' as only levels 2 - 5 are outliers).
            0 - The last four confidence levels
         */
        new CSVKeyBuilder().buildKeysForPredictedRows(0);
        new JSONKeyBuilder().buildKeysFromPhase5JSONObjects();  // To be used WITH the 'keySkip' filter in 'CSVKeyBuilder.java'.
        //new JSONKeyBuilder().buildKeysFromPhase4JSONObjects();  // To be used WITHOUT the 'keySkip' filter in 'CSVKeyBuilder.java'.
        new Evaluator().outputSetSizes();
        new Evaluator().getPrecision();
        new Evaluator().getRecall();
        new Evaluator().getAccuracy();
        new Evaluator().getF1Score();
    }

    public static Set<String> getAllCSVKeys() {
        return allCSVKeys;
    }

    public static void setAllCSVKeys(Set<String> allCSVKeys) {
        App.allCSVKeys = allCSVKeys;
    }

    public static HashSet<String> getPredictedKeys() {
        return predictedKeys;
    }

    public static void setPredictedKeys(HashSet<String> predictedKeys) {
        App.predictedKeys = predictedKeys;
    }

    public static HashSet<String> getGroundTruthJSONDataKeys() {
        return groundTruthJSONDataKeys;
    }

    public static void setGroundTruthJSONDataKeys(HashSet<String> groundTruthJSONDataKeys) {
        App.groundTruthJSONDataKeys = groundTruthJSONDataKeys;
    }

    public static HashMap<String, String> getCsvKeysAndConfidenceLevel() {
        return csvKeysAndConfidenceLevel;
    }

    public static void setCsvKeysAndConfidenceLevel(HashMap<String, String> csvKeysAndConfidenceLevel) {
        App.csvKeysAndConfidenceLevel = csvKeysAndConfidenceLevel;
    }

    public static HashSet<String> getKeysToSkip() {
        return keysToSkip;
    }

    public static void setKeysToSkip(HashSet<String> keysToSkip) {
        App.keysToSkip = keysToSkip;
    }

    public static boolean isApplyKeysToSkipFilter() {
        return applyKeysToSkipFilter;
    }

    public static void setApplyKeysToSkipFilter(boolean applyKeysToSkipFilter) {
        App.applyKeysToSkipFilter = applyKeysToSkipFilter;
    }
}
