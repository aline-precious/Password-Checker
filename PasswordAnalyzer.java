import java.util.*;
import java.util.regex.*;

/**
 * CIPHER — Java Password Analysis Engine
 * Mirrors the Python backend logic for use as a CLI tool.
 * Compile: javac -d out src/*.java
 * Run:     java -cp out PasswordChecker
 */
public class PasswordAnalyzer {

    private static final Pattern HAS_UPPER        = Pattern.compile("[A-Z]");
    private static final Pattern HAS_LOWER        = Pattern.compile("[a-z]");
    private static final Pattern HAS_DIGIT        = Pattern.compile("\\d");
    private static final Pattern HAS_SPECIAL      = Pattern.compile("[^A-Za-z0-9]");
    private static final Pattern REPEATED_CHARS   = Pattern.compile("(.)\\1{2,}");
    private static final Pattern SEQ_NUM          = Pattern.compile("(?:0123|1234|2345|3456|4567|5678|6789|7890)");
    private static final Pattern SEQ_ALPHA        = Pattern.compile("(?i)(?:abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz)");
    private static final Pattern KBD_WALK         = Pattern.compile("(?i)(?:qwer|wert|erty|rtyu|tyui|yuio|uiop|asdf|sdfg|dfgh|fghj|ghjk|hjkl|zxcv|xcvb|cvbn|vbnm|wasd)");
    private static final Pattern ALL_DIGITS       = Pattern.compile("^\\d+$");
    private static final Pattern ALL_ALPHA        = Pattern.compile("^[A-Za-z]+$");
    private static final Pattern LEET_SPEAK       = Pattern.compile("(?i)(?:p[a@]ssw[o0]rd|[a@]dmin|l[o0]gin|s[e3]cur[e3]|w[e3]lc[o0]m[e3])");
    private static final Pattern YEAR_PATTERN     = Pattern.compile("(?:19|20)\\d{2}");
    private static final Pattern RULE_BASED       = Pattern.compile("^(?:[a-zA-Z]+\\d{1,4}[!@#$]?|[A-Z][a-z]+\\d{1,4})$");

    private static final Set<String> COMMON = new HashSet<>(Arrays.asList(
        "password","password1","password123","123456","123456789","12345678","12345",
        "1234567","1234567890","qwerty","abc123","monkey","letmein","dragon","111111",
        "baseball","iloveyou","trustno1","sunshine","master","welcome","shadow",
        "ashley","football","jesus","michael","ninja","mustang","jessica","charlie",
        "donald","password2","qwerty123","admin","root","pass","test","guest","login",
        "hello","123","000000","654321","1q2w3e","superman","batman","access",
        "555555","lovely","666666","princess","starwars","solo","passw0rd","hunter2"
    ));

    private static final Set<String> DICT = new HashSet<>(Arrays.asList(
        "password","admin","user","login","welcome","hello","test","demo","default",
        "system","server","manager","computer","internet","network","security","access",
        "master","secret","private","public","super","root","home","work","office",
        "summer","winter","spring","autumn","monday","january","february","march",
        "abc","xyz","qwerty","dragon","monkey","shadow","sunshine","princess","baseball"
    ));

    public AnalysisResult analyze(String password) {
        AnalysisResult r = new AnalysisResult(password);
        runBasicChecks(password, r);
        runPatternChecks(password, r);
        runThreatSims(password, r);
        calcEntropy(password, r);
        calcScore(r);
        calcCrackTimes(password, r);
        return r;
    }

    private void runBasicChecks(String pw, AnalysisResult r) {
        int n = pw.length();
        r.addCheck("len8",    "Length ≥ 8",         n >= 8,   n < 8  ? n+" chars" : "Pass");
        r.addCheck("len12",   "Length ≥ 12",        n >= 12,  n < 12 ? "Only "+n+" chars" : "Pass");
        r.addCheck("len16",   "Length ≥ 16",        n >= 16,  n < 16 ? "Only "+n+" chars" : "Pass");
        r.addCheck("upper",   "Uppercase (A-Z)",    HAS_UPPER.matcher(pw).find(),   "Add uppercase letters");
        r.addCheck("lower",   "Lowercase (a-z)",    HAS_LOWER.matcher(pw).find(),   "Add lowercase letters");
        r.addCheck("digit",   "Contains digit",     HAS_DIGIT.matcher(pw).find(),   "Add 0-9 digits");
        r.addCheck("special", "Symbol !@#$%^&*",    HAS_SPECIAL.matcher(pw).find(), "Add special characters");
        r.addCheck("notall_digits","Not all digits", !ALL_DIGITS.matcher(pw).matches(), "Mix in letters");
        r.addCheck("notall_alpha", "Not all letters",!ALL_ALPHA.matcher(pw).matches(),  "Mix in digits/symbols");
    }

    private void runPatternChecks(String pw, AnalysisResult r) {
        String lo = pw.toLowerCase();

        boolean isCommon = COMMON.contains(lo);
        r.addPattern("nocommon","Not in breach list",    !isCommon, isCommon ? "⚠ Found in top breach database!" : "Not in common list");

        boolean hasDict = DICT.stream().anyMatch(w -> lo.contains(w) && w.length() >= 4);
        r.addPattern("nodict","No dictionary base word", !hasDict,  hasDict ? "Contains a common dictionary word" : "OK");

        boolean hasLeet = LEET_SPEAK.matcher(pw).find();
        r.addPattern("noleet","No leet-speak variant",   !hasLeet,  hasLeet ? "Leet-speak of 'password'/'admin' found" : "OK");

        boolean hasRep = REPEATED_CHARS.matcher(pw).find();
        r.addPattern("norepeat","No repeated chars (aaa)",!hasRep,  hasRep ? "3+ consecutive identical chars found" : "OK");

        boolean hasSeqN = SEQ_NUM.matcher(pw).find();
        r.addPattern("noseqnum","No sequential nums (1234)",!hasSeqN, hasSeqN ? "Sequential number run detected" : "OK");

        boolean hasSeqA = SEQ_ALPHA.matcher(pw).find();
        r.addPattern("noseqalph","No sequential abc",    !hasSeqA,  hasSeqA ? "Sequential letter run detected" : "OK");

        boolean hasKbd = KBD_WALK.matcher(pw).find();
        r.addPattern("nokbd","No keyboard walk (qwer)",  !hasKbd,   hasKbd ? "Keyboard walk pattern detected" : "OK");

        boolean hasYear = YEAR_PATTERN.matcher(pw).find();
        r.addPattern("noyear","No embedded year",        !hasYear,  hasYear ? "Contains a 4-digit year" : "OK");
    }

    private void runThreatSims(String pw, AnalysisResult r) {
        String lo = pw.toLowerCase();
        int pool = getPool(pw);
        double combos = Math.pow(pool, pw.length());
        double offline = combos / 1e10;

        boolean dictV = COMMON.contains(lo);
        r.addAttack("dict","Dictionary Attack","📖",dictV,
                dictV ? "VULNERABLE — exact match in wordlist" : "Resistant");

        boolean ruleV = RULE_BASED.matcher(pw).matches() && pw.length() < 12;
        r.addAttack("rule","Rule-Based (word+digit)","⚙",ruleV,
                ruleV ? "VULNERABLE — trivial word+number pattern" : "Resistant");

        boolean maskV = ALL_DIGITS.matcher(pw).matches() || pw.matches("[a-z]{4,8}") || pw.length() < 7;
        r.addAttack("mask","Mask Brute-Force","🎭",maskV,
                maskV ? "VULNERABLE — matches simple brute-force mask" : "Resistant");

        boolean hybridV = DICT.stream().anyMatch(w -> lo.startsWith(w) && pw.length()-w.length() <= 4);
        r.addAttack("hybrid","Hybrid Dict+Suffix","🧬",hybridV,
                hybridV ? "VULNERABLE — dictionary word with short suffix" : "Resistant");

        boolean stuffV = COMMON.contains(lo);
        r.addAttack("stuff","Credential Stuffing","🗄",stuffV,
                stuffV ? "VULNERABLE — found in breach database" : "Not in simulated breach list");

        boolean gpuV = offline < 3600;
        r.addAttack("brute","GPU Brute-Force","💻",gpuV,
                gpuV ? "VULNERABLE — crackable in "+formatTime(offline) : "Would take too long");
    }

    private void calcEntropy(String pw, AnalysisResult r) {
        int pool = getPool(pw);
        r.setEntropy(pw.length() * (Math.log(pool) / Math.log(2)));
        r.setPool(pool);
        r.setCombinations(Math.pow(pool, pw.length()));
    }

    private void calcScore(AnalysisResult r) {
        String pw = r.getPassword();
        int s = 0;
        s += Math.min(pw.length()*2, 30);
        if(HAS_LOWER.matcher(pw).find())   s += 5;
        if(HAS_UPPER.matcher(pw).find())   s += 5;
        if(HAS_DIGIT.matcher(pw).find())   s += 5;
        if(HAS_SPECIAL.matcher(pw).find()) s += 10;

        double ent = r.getEntropy();
        if(ent>=80) s+=20; else if(ent>=60) s+=12; else if(ent>=40) s+=6;

        s -= r.getFailedChecks()*3;
        s -= r.getFailedPatterns()*5;
        s -= r.getVulnerableAttacks()*8;

        r.setScore(Math.max(0, Math.min(100, s)));
    }

    private void calcCrackTimes(String pw, AnalysisResult r) {
        int pool = getPool(pw);
        double combos = Math.pow(pool, pw.length());
        r.setCrackOffline(formatTime(combos / 1e10));
        r.setCrackOnline(formatTime(combos / 100.0));
    }

    private int getPool(String pw) {
        int p = 0;
        if(HAS_LOWER.matcher(pw).find())   p += 26;
        if(HAS_UPPER.matcher(pw).find())   p += 26;
        if(HAS_DIGIT.matcher(pw).find())   p += 10;
        if(HAS_SPECIAL.matcher(pw).find()) p += 32;
        return p > 0 ? p : 10;
    }

    private String formatTime(double s) {
        if(s < 1)             return "< 1 second";
        if(s < 60)            return String.format("%.0f seconds", s);
        if(s < 3600)          return String.format("%.0f minutes", s/60);
        if(s < 86400)         return String.format("%.0f hours", s/3600);
        if(s < 2592000)       return String.format("%.0f days", s/86400);
        if(s < 31536000)      return String.format("%.0f months", s/2592000);
        if(s < 3.15e9)        return String.format("%.0f years", s/31536000);
        return "centuries";
    }
}
