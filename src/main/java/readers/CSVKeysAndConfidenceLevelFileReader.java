package readers;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;

public class CSVKeysAndConfidenceLevelFileReader {

    public HashMap<String, String> readCSVKeysAndConfidenceLevelFile() throws IOException {

        HashMap<String, String> csvKeysAndConfidenceLevel = new  HashMap<>();

        File csvKeys_and_confidenceLevel_file = new File("CSVKeysAndConfidenceLevel.txt");

        BufferedReader br = new BufferedReader(new FileReader(csvKeys_and_confidenceLevel_file));

        String line;

        // read file line by line
        while ((line = br.readLine()) != null) {

            // split the line by "<-->"
            String[] parts = line.split("<-->");

            // first part is key, second is confidence level.
            try {
                String key = parts[0].trim();
                String confidenceLevel = parts[1].trim();

                // Put key, confidence level in HashMap if they are both strings.
                if ((!key.equals("")) && (!confidenceLevel.equals(""))) {
                    csvKeysAndConfidenceLevel.put(key, confidenceLevel);
                }
            } catch (ArrayIndexOutOfBoundsException arrayIndexOutOfBoundsException) {
                System.err.println(Arrays.toString(parts));
            }
        }

        br.close();

        return csvKeysAndConfidenceLevel;
    }
}
