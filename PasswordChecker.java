import java.io.Console;
import java.util.Scanner;

public class PasswordChecker {

    public static void main(String[] args) {
        PasswordAnalyzer analyzer = new PasswordAnalyzer();
        TerminalRenderer renderer = new TerminalRenderer();

        if (args.length > 0) {
            // Batch mode: java -cp out PasswordChecker myPass1 myPass2
            for (String pw : args) {
                renderer.render(analyzer.analyze(pw));
            }
        } else {
            // Interactive REPL
            printWelcome();
            Console console = System.console();
            Scanner sc = new Scanner(System.in);

            while (true) {
                System.out.print("\033[96m  Enter password\033[0m (\033[90mtype 'quit' to exit\033[0m): ");

                String input;
                if (console != null) {
                    char[] ch = console.readPassword();
                    if (ch == null) break;
                    input = new String(ch);
                } else {
                    if (!sc.hasNextLine()) break;
                    input = sc.nextLine();
                }

                if (input.equalsIgnoreCase("quit") || input.equals("q") || input.equalsIgnoreCase("exit")) {
                    System.out.println("\n\033[96m  Stay secure! 🔐\033[0m\n");
                    break;
                }
                if (input.isBlank()) {
                    System.out.println("\033[91m  ⚠  Please enter a password.\033[0m\n");
                    continue;
                }

                renderer.render(analyzer.analyze(input));
            }
        }
    }

    private static void printWelcome() {
        System.out.println();
        System.out.println("\033[1m\033[96m  ╔═══════════════════════════════════════╗\033[0m");
        System.out.println("\033[1m\033[96m  ║   CIPHER Password Auditor  v1.0      ║\033[0m");
        System.out.println("\033[1m\033[96m  ╚═══════════════════════════════════════╝\033[0m");
        System.out.println("\033[90m  Checks strength, patterns, and attack resistance.\033[0m");
        System.out.println("\033[90m  Input is never stored or transmitted.\033[0m\n");
    }
}
