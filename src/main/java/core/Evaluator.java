package core;

import ucl.cdt.cybersecurity.App;

import java.util.HashSet;
import java.util.Set;

public class Evaluator {

    Set<String> allCSVKeys = App.getAllCSVKeys();
    HashSet<String> predictedKeys = App.getPredictedKeys();
    HashSet<String> groundTruthJSONDataKeys = App.getGroundTruthJSONDataKeys();

    double truePositives = getTruePositives();
    double falsePositives = getFalsePositives();
    double trueNegatives = getTrueNegatives();
    double falseNegatives = getFalseNegatives();

    public void outputSetSizes() {
        System.out.println("allCSVKeys: " + allCSVKeys.size());
        System.out.println("predictedKeys: " + predictedKeys.size());
        System.out.println("groundTruthJSONDataKeys: " + groundTruthJSONDataKeys.size());
    }

    public double getPrecision() {

        // Precision = True Positives/True Positives + False Positives.

        double precision = (truePositives> 0 && falsePositives > 0) ? truePositives/(truePositives + falsePositives) : -1;

        System.out.println("------------- Precision ---------------");
        System.out.println("True Positives: " + truePositives);
        System.out.println("False Positives: " + falsePositives);
        System.out.printf("Precision: %.5f\n", precision);
        System.out.println("---------------------------------------");

        assert precision < 1;

        return precision;
    }

    public double getRecall() {

        // Recall = True Positives/True Positives + False Negatives.

        double recall = (truePositives> 0 && falseNegatives > 0) ? truePositives/(truePositives + falseNegatives) : -1;

        System.out.println("------------- Recall ----------------");
        System.out.println("True Positives: " + truePositives);
        System.out.println("False Negatives: " + falseNegatives);
        System.out.printf("Recall: %.5f\n", recall);
        System.out.println("-------------------------------------");

        assert recall < 1;

        return recall;
    }

    public double getAccuracy() {

        // Accuracy = True Positives + True Negatives/(True Positives + False Positives + True Negatives + False Negatives)

        double accuracy = (truePositives> 0 && falsePositives > 0 && trueNegatives > 0 && falseNegatives > 0) ? (truePositives + trueNegatives)/(truePositives + falsePositives + trueNegatives + falseNegatives) : -1;

        System.out.println("------------- Accuracy ----------------");
        System.out.println("True Positives: " + truePositives);
        System.out.println("False Positives: " + falsePositives);
        System.out.println("True Negatives: " + trueNegatives);
        System.out.println("False Negatives: " + falseNegatives);
        System.out.printf("Accuracy: %.5f\n", accuracy);
        System.out.println("----------------------------------------");

        assert accuracy < 1;

        return accuracy;
    }

    public double getF1Score() {

        double precision = getPrecision();
        double recall = getRecall();

        double f1Score = (precision > 0 && recall > 0) ? 2 * ((precision * recall)/(precision + recall)) : -1;

        System.out.println("--------------- F1 Score ---------------");
        System.out.printf("Precision: %.5f\n", precision);
        System.out.printf("Recall: %.5f\n", recall);
        System.out.printf("F1 Score: %.5f\n", f1Score);
        System.out.println("----------------------------------------");

        assert f1Score < 1;

        return f1Score;
    }

    double getTruePositives() {

        HashSet<String> truePositives = new HashSet<>(predictedKeys);
        truePositives.retainAll(groundTruthJSONDataKeys); // Look for keys in the ground truth data that also appear in our predictions.
        //System.out.println("True Positives: " + truePositives.size());

        return truePositives.size();
    }

    double getFalsePositives() {

        HashSet<String> falsePositives = new HashSet<>(predictedKeys);
        falsePositives.removeAll(groundTruthJSONDataKeys); // Remove the  keys from the ground truth data that appear in our predictions, the remainder would be keys falsely identified as 'vulnerable'.
        //System.out.println("False Positives: " + falsePositives.size());

        return falsePositives.size();
    }

    double getTrueNegatives() {

        Set<String> trueNegatives = new HashSet<>(allCSVKeys);
        trueNegatives.removeAll(predictedKeys); // Remove all predicted keys from all our keys, then...
        trueNegatives.removeAll(groundTruthJSONDataKeys); // Remove all keys that appear in the ground truth. The remaining keys would truly not be vulnerable.
        //System.out.println("True Negatives: " + trueNegatives.size());

        return trueNegatives.size();
    }

    double getFalseNegatives() {

        Set<String> falseNegatives =  new HashSet<>(allCSVKeys);
        falseNegatives.removeAll(predictedKeys); // Remove all predicted keys from all our keys to get the predicted results out of the way, then...
        falseNegatives.retainAll(groundTruthJSONDataKeys); // Look for keys in the ground truth data that are also present in the remaining keys. Those retained would be vulnerable keys that have been mistakenly identified as 'invulnerable' in our prediction.
        //System.out.println("False Negatives: " + falseNegatives.size());

        return falseNegatives.size();
    }
}
