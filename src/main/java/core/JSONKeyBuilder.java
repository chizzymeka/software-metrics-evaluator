package core;

import org.json.JSONArray;
import org.json.JSONObject;
import ucl.cdt.cybersecurity.App;
import utilities.CurrentTime;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

public class JSONKeyBuilder {

    HashSet<String> groundTruthJSONDataKeys = App.getGroundTruthJSONDataKeys();

    public void buildKeysFromPhase5JSONObjects() throws IOException {

        System.out.println("Building ground truth data keys...[" + new CurrentTime().getCurrentTimeStamp() + "]");

        App.setApplyKeysToSkipFilter(true);

        FileWriter fileWriter = new FileWriter("groundTruthJSONDataKeys.txt");

        String groundTruthDataPhase5path = "src/main/java/ground-truth-data/ground_truth_phase_5.json";
        String groundTruthDataPhase5Data = new String((Files.readAllBytes(Paths.get(groundTruthDataPhase5path))));
        JSONArray resolutionVersionObjects = new JSONArray(groundTruthDataPhase5Data);

        for (int i = 0; i < resolutionVersionObjects.length(); i++) {

            JSONObject resolutionVersionObject = resolutionVersionObjects.getJSONObject(i);
            Set<JSONObject> resolutionVersionObjectKeys = resolutionVersionObject.keySet();

            for (Object resolutionVersionObjectKey : resolutionVersionObjectKeys) {

                String resolutionVersion = (String) resolutionVersionObjectKey;
                JSONObject cveIdObject = (JSONObject) resolutionVersionObject.get(resolutionVersion);
                Set<JSONObject> cveIdObjectKeys = cveIdObject.keySet();

                for (Object cveIdObjectKey : cveIdObjectKeys) {

                    String cveId = (String) cveIdObjectKey;
                    JSONObject commitObject = (JSONObject) cveIdObject.get(cveId);
                    Set<JSONObject> commitObjectKeys = commitObject.keySet();

                    for (Object commitObjectKey : commitObjectKeys) {

                        String commitId = (String) commitObjectKey;
                        JSONObject commitUrlObject = (JSONObject) commitObject.get(commitId);
                        Set<JSONObject> commitUrlObjectKeys = commitUrlObject.keySet();

                        for (Object commitUrlObjectKey : commitUrlObjectKeys) {

                            String commitUrl = (String) commitUrlObjectKey;
                            JSONObject fileSuffixObject = (JSONObject) commitUrlObject.get(commitUrl);
                            Set<JSONObject> filePathSuffixObjectKeys = fileSuffixObject.keySet();

                            for (Object filePathSuffixObjectKey : filePathSuffixObjectKeys) {

                                String filePathSuffix = (String) filePathSuffixObjectKey;
                                JSONObject vulnerableComponentsObjects = (JSONObject) fileSuffixObject.get(filePathSuffix);
                                JSONObject classObjects = (JSONObject) vulnerableComponentsObjects.get("vulnerableComponents");
                                Set<JSONObject> classNameObjectKeys = classObjects.keySet();

                                for (Object classNameObjectKey : classNameObjectKeys) {

                                    String className = (String) classNameObjectKey;
                                    JSONArray methodSignatureObjects = (JSONArray) classObjects.get(className);

                                    for (int j=0; j < methodSignatureObjects.length(); j++) {
                                        String methodSignature = (String) methodSignatureObjects.get(j);
                                        String key = resolutionVersion + "=+=" + "/" + filePathSuffix + "=+=" + className + "=+=" + methodSignature; // Included the "/" before 'filePathSuffix' to make the key format match with the CSV format.
                                        groundTruthJSONDataKeys.add(key);
                                        fileWriter.write(key + "\n");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        fileWriter.close();
    }

    public void buildKeysFromPhase4JSONObjects() throws IOException {

        System.out.println("Building ground truth data keys...[" + new CurrentTime().getCurrentTimeStamp() + "]");

        App.setApplyKeysToSkipFilter(false);

        FileWriter fileWriter = new FileWriter("groundTruthJSONDataKeys.txt");

        String lineNumber;
        String groundTruthDataPhase4path = "src/main/java/ground-truth-data/ground_truth_phase_4.json";
        String groundTruthDataPhase4Data = new String((Files.readAllBytes(Paths.get(groundTruthDataPhase4path))));
        JSONArray resolutionVersionObjects = new JSONArray(groundTruthDataPhase4Data);

        for (int i = 0; i < resolutionVersionObjects.length(); i++) {

            JSONObject resolutionVersionObject = resolutionVersionObjects.getJSONObject(i);
            Set<JSONObject> resolutionVersionObjectKeys = resolutionVersionObject.keySet();

            for (Object resolutionVersionObjectKey : resolutionVersionObjectKeys) {

                String resolutionVersion = (String) resolutionVersionObjectKey;
                System.out.println("Building keys for: " + resolutionVersion);
                JSONObject cveIdObject = (JSONObject) resolutionVersionObject.get(resolutionVersion);
                Set<JSONObject> cveIdObjectKeys = cveIdObject.keySet();

                for (Object cveIdObjectKey : cveIdObjectKeys) {

                    String cveId = (String) cveIdObjectKey;
                    JSONObject cveIdObj = (JSONObject) cveIdObject.get(cveId);
                    JSONObject commitObject = (JSONObject) cveIdObj.get("vulnerabilityFixLocations");
                    Set<JSONObject> commitObjectKeys = commitObject.keySet();

                    for (Object commitObjectKey : commitObjectKeys) {

                        String commitId = (String) commitObjectKey;
                        JSONObject commitUrlObject = (JSONObject) commitObject.get(commitId);
                        Set<JSONObject> commitUrlObjectKeys = commitUrlObject.keySet();

                        for (Object commitUrlObjectKey : commitUrlObjectKeys) {

                            String commitUrl = (String) commitUrlObjectKey;
                            JSONObject fileSuffixObject = (JSONObject) commitUrlObject.get(commitUrl);
                            Set<JSONObject> filePathSuffixObjectKeys = fileSuffixObject.keySet();

                            for (Object filePathSuffixObjectKey : filePathSuffixObjectKeys) {

                                String filePathSuffix = (String) filePathSuffixObjectKey;
                                JSONObject lineNumberObject = (JSONObject) fileSuffixObject.get(filePathSuffix);
                                Set<JSONObject> lineNumberObjectKeys = lineNumberObject.keySet();

                                for (Object lineNumberObjectKey : lineNumberObjectKeys) {

                                    lineNumber = (String) lineNumberObjectKey;
                                    JSONObject classAndMethodObject = (JSONObject) lineNumberObject.get(lineNumber);
                                    String methodSignature = (String) classAndMethodObject.get("methodSignature");
                                    String className = (String) classAndMethodObject.get("className");

                                    if ((className != null && methodSignature != null) && (!className.equals("") && !methodSignature.equals("")) && (!className.equals("no_class_name") && !methodSignature.equals("no_method_signature"))) {
                                        String key = resolutionVersion + "=+=" + "/" + filePathSuffix + "=+=" + className + "=+=" + methodSignature; // Included the "/" before 'filePathSuffix' to make the key format match with the CSV format.
                                        groundTruthJSONDataKeys.add(key);
                                        fileWriter.write(key + "\n");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        fileWriter.close();
    }
}
