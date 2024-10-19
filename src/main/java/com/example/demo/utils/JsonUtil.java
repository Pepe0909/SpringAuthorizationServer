package com.example.demo.utils;

import com.nimbusds.jose.shaded.gson.Gson;

public class JsonUtil {

    private JsonUtil () {
        throw new IllegalStateException("err0r");
    }


    public static <T> T  convertJsonToPojo (String json, Class<T> pojoClass) {
        Gson gson = new Gson();
        return gson.fromJson(json, pojoClass);
    }
}
