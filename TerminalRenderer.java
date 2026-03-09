import java.util.List;

public class TerminalRenderer {

    private static final String R  = "\033[0m";
    private static final String B  = "\033[1m";
    private static final String DM = "\033[2m";
    private static final String RED    = "\033[91m";
    private static final String GREEN  = "\033[92m";
    private static final String YELLOW = "\033[93m";
    private static final String CYAN   = "\033[96m";
    private static final String WHITE  = "\033[97m";
    private static final String GRAY   = "\033[90m";

    public void render(AnalysisResult r) {
        banner();
        header(r);
        scoreBar(r);
        crackTimes(r);
        section("BASIC RULES", r.getChecks());
        section("PATTERN ANALYSIS", r.getPatterns());
        attacks(r);
        recommendations(r);
        footer();
    }

    private void banner() {
        System.out.println();
        System.out.println(CYAN+B+"╔═══════════════════════════════════════════════════════════════╗"+R);
        System.out.println(CYAN+B+"║  "+WHITE+"🔐 CIPHER — Password Threat Intelligence"+GRAY+"  ─────────────"+CYAN+"  ║"+R);
        System.out.println(CYAN+B+"╚═══════════════════════════════════════════════════════════════╝"+R);
        System.out.println();
    }

    private void header(AnalysisResult r) {
        String col = scoreCol(r.getScore());
        System.out.printf("  %sStrength:%s %s%s%s   %s(score: %d/100)%s%n",
                B, R, col+B, r.getStrength(), R, GRAY, r.getScore(), R);
        System.out.printf("  %sEntropy: %s%s%.1f bits%s%n%n",
                B, R, CYAN, r.getEntropy(), R);
    }

    private void scoreBar(AnalysisResult r) {
        int filled = (int) Math.round(r.getScore() / 100.0 * 50);
        String col = scoreCol(r.getScore());
        System.out.print("  "+GRAY+"["+R + col + "█".repeat(filled) + R
                + GRAY + "░".repeat(50-filled) + "] "
                + col + B + r.getScore() + "%" + R + "%n%n");
        System.out.printf("  "+GRAY+"["+R+col+"%-50s"+GRAY+"] "+col+B+"%d%%"+R+"%n%n",
                "█".repeat(filled), r.getScore());
    }

    private void crackTimes(AnalysisResult r) {
        sectionHead("CRACK TIME ESTIMATES");
        System.out.printf("  %-40s %s%s%s%n",
                GRAY+"Offline (10B guesses/sec — GPU rig):"+R,
                RED+B, r.getCrackOffline(), R);
        System.out.printf("  %-40s %s%s%s%n%n",
                GRAY+"Online  (100 guesses/sec — throttled):"+R,
                YELLOW+B, r.getCrackOnline(), R);
    }

    private void section(String title, List<AnalysisResult.CheckItem> items) {
        sectionHead(title);
        for (AnalysisResult.CheckItem c : items) {
            String ico = c.passed ? GREEN+"✔" : RED+"✘";
            String det = c.passed ? GRAY+c.detail : RED+c.detail;
            System.out.printf("  %s%s  %-40s %s%s%n", ico, R, c.label, det, R);
        }
        System.out.println();
    }

    private void attacks(AnalysisResult r) {
        sectionHead("ATTACK SIMULATION RESULTS");
        for (AnalysisResult.AttackItem a : r.getAttacks()) {
            String ico = a.vulnerable ? RED+"✘" : GREEN+"✔";
            String st  = a.vulnerable ? RED+B+"CRACKED"+R : GREEN+B+"BLOCKED"+R;
            String det = a.vulnerable ? RED+a.detail : GRAY+a.detail;
            System.out.printf("  %s%s  %-36s [%s]  %s%s%n",
                    ico, R, a.icon+" "+a.name, st, det, R);
        }
        System.out.println();
    }

    private void recommendations(AnalysisResult r) {
        List<AnalysisResult.CheckItem> fails = r.getChecks().stream().filter(c->!c.passed).toList();
        List<AnalysisResult.CheckItem> pfails= r.getPatterns().stream().filter(c->!c.passed).toList();
        List<AnalysisResult.CheckItem> all = new java.util.ArrayList<>();
        all.addAll(fails); all.addAll(pfails);

        sectionHead("RECOMMENDATIONS");
        if(all.isEmpty()) {
            System.out.println("  "+GREEN+B+"✔  No issues — excellent password!"+R);
        } else {
            int i=1;
            for(AnalysisResult.CheckItem c : all) {
                System.out.printf("  %s%d.%s %-38s → %s%s%s%n",
                        YELLOW+B, i++, R, c.label+":", GRAY, c.detail, R);
            }
        }
        System.out.println();
        System.out.println("  "+CYAN+"💡 Passphrase tip:"+R+" 4 random words ≈ 50 bits entropy");
        System.out.println("     "+GRAY+"e.g. "+WHITE+"correct-horse-battery-staple"+R);
        System.out.println();
    }

    private void footer() {
        System.out.println(GRAY+"  "+"─".repeat(63)+R);
        System.out.println(GRAY+"  Passwords are never stored or transmitted. Stay secure! 🔐"+R);
        System.out.println();
    }

    private void sectionHead(String title) {
        System.out.println("  "+CYAN+B+"▸ "+WHITE+title+R);
        System.out.println("  "+GRAY+"─".repeat(61)+R);
    }

    private String scoreCol(int s) {
        if(s>=80) return GREEN;
        if(s>=60) return CYAN;
        if(s>=35) return YELLOW;
        return RED;
    }
}
