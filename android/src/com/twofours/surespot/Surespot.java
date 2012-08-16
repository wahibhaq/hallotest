package com.twofours.surespot;

import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.support.v4.app.NavUtils;
import org.apache.cordova.*;

public class Surespot extends DroidGap {

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        super.loadUrl("file:///android_asset/html/layout.html");
        //super.loadUrl("http://alpha.surespot.me");
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_surespot, menu);
        return true;
    }

    
}
