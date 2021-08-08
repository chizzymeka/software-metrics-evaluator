package utilities;

import java.sql.Timestamp;
import java.util.Date;

public class CurrentTime {

    public Timestamp getCurrentTimeStamp() {

        Date date = new Date();
        long time = date.getTime();
        Timestamp timestamp = new Timestamp(time);

        return timestamp;
    }

}
