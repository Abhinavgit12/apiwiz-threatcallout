// 
// Decompiled by Procyon v0.5.36
// 

package com.apiwiz.security.threatcheck;
import lombok.Data;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;

@Data
public class RegularExpressionChecker extends Thread {
    protected List<Pattern> patterns;
    private String toMatch;
    protected String patternMatched;
    protected boolean matched;


    protected RegularExpressionChecker(final List<Pattern> patterns, final String name) {
        super(name);
        this.patterns = patterns;
    }

    public RegularExpressionChecker(final List<Pattern> patterns, final String toMatch, final String name) {
        super(name);
        this.patterns = patterns;
        this.toMatch = toMatch;
    }

    @Override
    public void run() {
        if (this.patterns == null || this.patterns.isEmpty()) {
            return;
        }
        this.patternMatched = null;
        for (final Pattern pattern : this.patterns) {
            final Matcher matcher = pattern.matcher(this.toMatch);
            this.matched = matcher.find();
            if (this.matched) {
                this.patternMatched = pattern.pattern();
                break;
            }
        }
    }
}
