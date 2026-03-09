import java.util.*;

public class AnalysisResult {

    public static class CheckItem {
        public final String id, label, detail;
        public final boolean passed;
        public CheckItem(String id, String label, boolean passed, String detail) {
            this.id=id; this.label=label; this.passed=passed; this.detail=detail;
        }
    }

    public static class AttackItem {
        public final String id, name, icon, detail;
        public final boolean vulnerable;
        public AttackItem(String id, String name, String icon, boolean vulnerable, String detail) {
            this.id=id; this.name=name; this.icon=icon; this.vulnerable=vulnerable; this.detail=detail;
        }
    }

    private final String password;
    private final List<CheckItem>  checks   = new ArrayList<>();
    private final List<CheckItem>  patterns = new ArrayList<>();
    private final List<AttackItem> attacks  = new ArrayList<>();

    private double entropy, combinations;
    private int pool, score;
    private String crackOffline, crackOnline;

    public AnalysisResult(String password) { this.password = password; }

    public void addCheck(String id, String label, boolean passed, String detail) {
        checks.add(new CheckItem(id, label, passed, detail));
    }
    public void addPattern(String id, String label, boolean passed, String detail) {
        patterns.add(new CheckItem(id, label, passed, detail));
    }
    public void addAttack(String id, String name, String icon, boolean vulnerable, String detail) {
        attacks.add(new AttackItem(id, name, icon, vulnerable, detail));
    }

    public int getFailedChecks()    { return (int) checks.stream().filter(c->!c.passed).count(); }
    public int getFailedPatterns()  { return (int) patterns.stream().filter(c->!c.passed).count(); }
    public int getVulnerableAttacks(){ return (int) attacks.stream().filter(a->a.vulnerable).count(); }

    public String getPassword()    { return password; }
    public List<CheckItem>  getChecks()   { return checks; }
    public List<CheckItem>  getPatterns() { return patterns; }
    public List<AttackItem> getAttacks()  { return attacks; }

    public double getEntropy()    { return entropy; }
    public void   setEntropy(double e) { this.entropy = e; }
    public int    getPool()       { return pool; }
    public void   setPool(int p)  { this.pool = p; }
    public double getCombinations()    { return combinations; }
    public void   setCombinations(double c) { this.combinations = c; }
    public int    getScore()      { return score; }
    public void   setScore(int s) { this.score = s; }
    public String getCrackOffline()    { return crackOffline; }
    public void   setCrackOffline(String t) { this.crackOffline = t; }
    public String getCrackOnline()     { return crackOnline; }
    public void   setCrackOnline(String t)  { this.crackOnline = t; }

    public String getStrength() {
        if(score>=80) return "FORTRESS";
        if(score>=60) return "SECURE";
        if(score>=35) return "VULNERABLE";
        return "CRITICAL";
    }
}
