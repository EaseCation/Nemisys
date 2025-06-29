package org.itxtech.nemisys.lang;

import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.utils.Utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class BaseLang {
    public static final String FALLBACK_LANGUAGE = "eng";

    protected String langName;

    protected final Map<String, String> lang;
    protected final Map<String, String> fallbackLang;

    public BaseLang(String lang) {
        this(lang, null);
    }

    public BaseLang(String lang, String path) {
        this(lang, path, FALLBACK_LANGUAGE);
    }

    public BaseLang(String lang, String path, String fallback) {
        this.langName = lang.toLowerCase();

        if (path == null) {
            path = "lang/";
            this.lang = this.loadLang(this.getClass().getClassLoader().getResourceAsStream(path + this.langName + "/lang.ini"));
            this.fallbackLang = this.loadLang(this.getClass().getClassLoader().getResourceAsStream(path + fallback + "/lang.ini"));
        } else {
            this.lang = this.loadLang(path + this.langName + "/lang.ini");
            this.fallbackLang = this.loadLang(path + fallback + "/lang.ini");
        }
    }

    public String getName() {
        return this.get("language.name");
    }

    public String getLang() {
        return langName;
    }

    protected Map<String, String> loadLang(String path) {
        try {
            String content = Utils.readFile(path);
            Map<String, String> d = new Object2ObjectOpenHashMap<>();
            for (String line : content.split("\n")) {
                line = line.trim();
                if (line.isEmpty() || line.charAt(0) == '#') {
                    continue;
                }
                String[] t = line.split("=");
                if (t.length < 2) {
                    continue;
                }
                String key = t[0];
                StringBuilder value = new StringBuilder();
                for (int i = 1; i < t.length - 1; i++) {
                    value.append(t[i]).append("=");
                }
                value.append(t[t.length - 1]);
                if (value.isEmpty()) {
                    continue;
                }
                d.put(key, value.toString());
            }
            return d;
        } catch (IOException e) {
            Server.getInstance().getLogger().logException(e);
            return null;
        }
    }

    protected Map<String, String> loadLang(InputStream stream) {
        try {
            String content = Utils.readFile(stream);
            Map<String, String> d = new Object2ObjectOpenHashMap<>();
            for (String line : content.split("\n")) {
                line = line.trim();
                if (line.isEmpty() || line.charAt(0) == '#') {
                    continue;
                }
                String[] t = line.split("=");
                if (t.length < 2) {
                    continue;
                }
                String key = t[0];
                StringBuilder value = new StringBuilder();
                for (int i = 1; i < t.length - 1; i++) {
                    value.append(t[i]).append("=");
                }
                value.append(t[t.length - 1]);
                if (value.isEmpty()) {
                    continue;
                }
                d.put(key, value.toString());
            }
            return d;
        } catch (IOException e) {
            Server.getInstance().getLogger().logException(e);
            return null;
        }
    }

    public String translateString(String str) {
        return this.translateString(str, new String[]{}, null);
    }

    public String translateString(String str, String param) {
        return this.translateString(str, new String[]{param});
    }

    public String translateString(String str, String[] params) {
        return this.translateString(str, params, null);
    }

    public String translateString(String str, String param, String onlyPrefix) {
        return this.translateString(str, new String[]{param}, onlyPrefix);
    }

    public String translateString(String str, String[] params, String onlyPrefix) {
        String baseText = this.get(str);
        baseText = this.parseTranslation((baseText != null && (onlyPrefix == null || str.indexOf(onlyPrefix) == 0)) ? baseText : str, onlyPrefix);
        for (int i = 0; i < params.length; i++) {
            baseText = baseText.replace("{%" + i + "}", this.parseTranslation(params[i]));
        }

        return baseText;
    }

    public String translate(TextContainer c) {
        String baseText = this.parseTranslation(c.getText());
        if (c instanceof TranslationContainer) {
            baseText = this.internalGet(c.getText());
            baseText = this.parseTranslation(baseText != null ? baseText : c.getText());
            for (int i = 0; i < ((TranslationContainer) c).getParameters().length; i++) {
                baseText = baseText.replace("{%" + i + "}", this.parseTranslation(((TranslationContainer) c).getParameters()[i]));
            }
        }
        return baseText;
    }

    public String internalGet(String id) {
        String text = this.lang.get(id);
        if (text != null) {
            return text;
        }
        return this.fallbackLang.get(id);
    }

    public String get(String id) {
        String text = this.lang.get(id);
        if (text != null) {
            return text;
        }
        String fallback = this.fallbackLang.get(id);
        if (fallback != null) {
            return fallback;
        }
        return id;
    }

    protected String parseTranslation(String text) {
        return this.parseTranslation(text, null);
    }

    protected String parseTranslation(String text, String onlyPrefix) {
        StringBuilder newString = new StringBuilder();

        StringBuilder replaceString = null;

        int len = text.length();

        for (int i = 0; i < len; ++i) {
            char c = text.charAt(i);
            if (replaceString != null) {
                if (((int) c >= 0x30 && (int) c <= 0x39) // 0-9
                        || ((int) c >= 0x41 && (int) c <= 0x5a) // A-Z
                        || ((int) c >= 0x61 && (int) c <= 0x7a) || // a-z
                        c == '.' || c == '-') {
                    replaceString.append(c);
                } else {
                    String t = this.internalGet(replaceString.substring(1));
                    if (t != null && (onlyPrefix == null || replaceString.indexOf(onlyPrefix) == 1)) {
                        newString.append(t);
                    } else {
                        newString.append(replaceString);
                    }
                    replaceString = null;
                    if (c == '%') {
                        replaceString = new StringBuilder(String.valueOf(c));
                    } else {
                        newString.append(c);
                    }
                }
            } else if (c == '%') {
                replaceString = new StringBuilder(String.valueOf(c));
            } else {
                newString.append(c);
            }
        }

        if (replaceString != null) {
            String t = this.internalGet(replaceString.substring(1));
            if (t != null && (onlyPrefix == null || replaceString.indexOf(onlyPrefix) == 1)) {
                newString.append(t);
            } else {
                newString.append(replaceString);
            }
        }
        return newString.toString();
    }
}
