package com.apiwiz.security.threatcheck;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;
import java.util.Map;

public class RegularExpressionCheckerMap extends RegularExpressionChecker
{
    private Map<String, Object> toMatch;

    public RegularExpressionCheckerMap(final List<Pattern> patterns, final Map<String, Object> toMatch, final String name) {
        super(patterns, name);
        this.toMatch = toMatch;
    }

    @Override
    public void run() {
        if (this.patterns == null || this.patterns.isEmpty()) {
            return;
        }
        this.patternMatched = null;
        for (final Pattern pattern : this.patterns) {
            for (final Map.Entry<String, Object> entry : this.toMatch.entrySet()) {
                final Object valuesToMatch = entry.getValue();
                String s = valuesToMatch.toString();
                String aa=String.valueOf(pattern);
                CharSequence cs = s;
                Pattern p = Pattern.compile(String.valueOf(pattern),Pattern.CASE_INSENSITIVE);
                final Matcher matcher = p.matcher(s);
                this.matched = matcher.find();

                if (this.matched) {
                    this.patternMatched = pattern.pattern();
                    this.setName(this.getName() + "_" + entry.getKey());
                }
                if (this.matched) {
                    break;
                }
            }
            if (this.matched) {
                break;
            }
        }
    }
}