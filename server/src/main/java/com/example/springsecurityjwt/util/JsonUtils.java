package com.example.springsecurityjwt.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.lang.reflect.Type;

public class JsonUtils {

    private static JsonUtils instance;

    private Gson gson;
    private Gson prettyGson;

    /**
     * disableHtmlEscaping : Html 문자를 변환하지 않도록 설정 (&lt; &gt; 같은 문자로 변환하지 않고 < > 그대로 출력되도록)
     * setPrettyPrinting : Json 데이터를 출력할 때 가시성이 좋도록 출력 포맷을 만들어준다.
     */
    private JsonUtils() {
        gson = new GsonBuilder().disableHtmlEscaping().create();
        prettyGson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
    }

    public static JsonUtils getInstance() {
        if(instance == null)
            instance = new JsonUtils();
        return instance;
    }

    private static Gson getGson(){
        return getInstance().gson;
    }

    private static Gson getPrettyGson(){
        return getInstance().prettyGson;
    }

    public static JsonElement parse(String jsonStr){ return JsonParser.parseString(jsonStr);}

    public static String toJson(Object obj) {
        return getGson().toJson(obj);
    }

    public static <T> T fromJson(String jsonStr, Class<T> cls) {
        return getGson().fromJson(jsonStr, cls);
    }

    public static <T> T fromJson(String jsonStr, Type type) {
        return getGson().fromJson(jsonStr, type);
    }

    public static String toPrettyJson(Object obj) {
        return getPrettyGson().toJson(obj);
    }
}
