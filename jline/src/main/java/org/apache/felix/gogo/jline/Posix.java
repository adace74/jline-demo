/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.felix.gogo.jline;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.IntBinaryOperator;
import java.util.function.IntConsumer;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.felix.service.command.Process;
import org.apache.felix.gogo.jline.Shell.Context;
import org.apache.felix.service.command.CommandProcessor;
import org.apache.felix.service.command.CommandSession;
import org.jline.builtins.Commands;
import org.jline.builtins.Less;
import org.jline.builtins.Nano;
import org.jline.builtins.Options;
import org.jline.builtins.Source;
import org.jline.builtins.Source.PathSource;
import org.jline.builtins.Source.StdInSource;
import org.jline.builtins.TTop;
import org.jline.terminal.Attributes;
import org.jline.terminal.Terminal;
import org.jline.utils.AttributedString;
import org.jline.utils.AttributedStringBuilder;
import org.jline.utils.AttributedStyle;
import org.jline.utils.InfoCmp.Capability;
import org.jline.utils.OSUtils;

/**
 * Posix-like utilities.
 *
 * @see <a href="http://www.opengroup.org/onlinepubs/009695399/utilities/contents.html">
 * http://www.opengroup.org/onlinepubs/009695399/utilities/contents.html</a>
 */
public class Posix {

    static final String[] functions;

    static {
        // TTop function is new in JLine 3.2
        String[] func;
        try {
            Class cl = TTop.class;
            func = new String[] {
                    "pwd", "ls"
            };
        } catch (Throwable t) {
            func = new String[] {
                    "pwd", "ls"
            };
        }
        functions = func;
    }

    public static final String DEFAULT_LS_COLORS = "dr=1;91:ex=1;92:sl=1;96:ot=34;43";
    public static final String DEFAULT_GREP_COLORS = "mt=1;31:fn=35:ln=32:se=36";

    private static final LinkOption[] NO_FOLLOW_OPTIONS = new LinkOption[]{LinkOption.NOFOLLOW_LINKS};
    private static final List<String> WINDOWS_EXECUTABLE_EXTENSIONS = Collections.unmodifiableList(Arrays.asList(".bat", ".exe", ".cmd"));
    private static final LinkOption[] EMPTY_LINK_OPTIONS = new LinkOption[0];

    private final CommandProcessor processor;

    public Posix(CommandProcessor processor) {
        this.processor = processor;
    }

    public void _main(CommandSession session, String[] argv) {
        if (argv == null || argv.length < 1) {
            throw new IllegalArgumentException();
        }
        Process process = Process.Utils.current();
        try {
            run(session, process, argv);
        } catch (IllegalArgumentException e) {
            process.err().println(e.getMessage());
            process.error(2);
        } catch (HelpException e) {
            process.err().println(e.getMessage());
            process.error(0);
        } catch (Exception e) {
            process.err().println(argv[0] + ": " + e.toString());
            process.error(1);
        }
    }

    protected static class HelpException extends Exception {
        public HelpException(String message) {
            super(message);
        }
    }

    protected Options parseOptions(CommandSession session, String[] usage, Object[] argv) throws Exception {
        Options opt = Options.compile(usage, s -> get(session, s)).parse(argv, true);
        if (opt.isSet("help")) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            opt.usage(new PrintStream(baos));
            throw new HelpException(baos.toString());
        }
        return opt;
    }

    protected String get(CommandSession session, String name) {
        Object o = session.get(name);
        return o != null ? o.toString() : null;
    }

    protected Object run(CommandSession session, Process process, String[] argv) throws Exception {
        switch (argv[0]) {
            case "pwd":
                pwd(session, process, argv);
                break;
            case "ls":
                ls(session, process, argv);
                break;
        }
        return null;
    }

    private String toJavaDateFormat(String format) {
        // transform Unix format to Java SimpleDateFormat (if required)
        StringBuilder sb = new StringBuilder();
        boolean quote = false;
        for (int i = 0; i < format.length(); i++) {
            char c = format.charAt(i);
            if (c == '%') {
                if (i + 1 < format.length()) {
                    if (quote) {
                        sb.append('\'');
                        quote = false;
                    }
                    c = format.charAt(++i);
                    switch (c) {
                        case '+':
                        case 'A': sb.append("MMM EEE d HH:mm:ss yyyy"); break;
                        case 'a': sb.append("EEE"); break;
                        case 'B': sb.append("MMMMMMM"); break;
                        case 'b': sb.append("MMM"); break;
                        case 'C': sb.append("yy"); break;
                        case 'c': sb.append("MMM EEE d HH:mm:ss yyyy"); break;
                        case 'D': sb.append("MM/dd/yy"); break;
                        case 'd': sb.append("dd"); break;
                        case 'e': sb.append("dd"); break;
                        case 'F': sb.append("yyyy-MM-dd"); break;
                        case 'G': sb.append("YYYY"); break;
                        case 'g': sb.append("YY"); break;
                        case 'H': sb.append("HH"); break;
                        case 'h': sb.append("MMM"); break;
                        case 'I': sb.append("hh"); break;
                        case 'j': sb.append("DDD"); break;
                        case 'k': sb.append("HH"); break;
                        case 'l': sb.append("hh"); break;
                        case 'M': sb.append("mm"); break;
                        case 'm': sb.append("MM"); break;
                        case 'N': sb.append("S"); break;
                        case 'n': sb.append("\n"); break;
                        case 'P': sb.append("aa"); break;
                        case 'p': sb.append("aa"); break;
                        case 'r': sb.append("hh:mm:ss aa"); break;
                        case 'R': sb.append("HH:mm"); break;
                        case 'S': sb.append("ss"); break;
                        case 's': sb.append("S"); break;
                        case 'T': sb.append("HH:mm:ss"); break;
                        case 't': sb.append("\t"); break;
                        case 'U': sb.append("w"); break;
                        case 'u': sb.append("u"); break;
                        case 'V': sb.append("W"); break;
                        case 'v': sb.append("dd-MMM-yyyy"); break;
                        case 'W': sb.append("w"); break;
                        case 'w': sb.append("u"); break;
                        case 'X': sb.append("HH:mm:ss"); break;
                        case 'x': sb.append("MM/dd/yy"); break;
                        case 'Y': sb.append("yyyy"); break;
                        case 'y': sb.append("yy"); break;
                        case 'Z': sb.append("z"); break;
                        case 'z': sb.append("X"); break;
                        case '%': sb.append("%"); break;
                    }
                } else {
                    if (!quote) {
                        sb.append('\'');
                    }
                    sb.append(c);
                    sb.append('\'');
                }
            } else {
                if ((c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') && !quote) {
                    sb.append('\'');
                    quote = true;
                }
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private void startShell(CommandSession session, Terminal terminal) {
        new Thread(() -> runShell(session, terminal), terminal.getName() + " shell").start();
    }

    private void runShell(CommandSession session, Terminal terminal) {
        InputStream in = terminal.input();
        OutputStream out = terminal.output();
        CommandSession newSession = processor.createSession(in, out, out);
        newSession.put(Shell.VAR_TERMINAL, terminal);
        newSession.put(".tmux", session.get(".tmux"));
        Context context = new Context() {
            public String getProperty(String name) {
                return System.getProperty(name);
            }
            public void exit() throws Exception {
                terminal.close();
            }
        };
        try {
            new Shell(context, processor).gosh(newSession, new String[]{"--login"});
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                terminal.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    protected void pwd(CommandSession session, Process process, String[] argv) throws Exception {
        final String[] usage = {
                "pwd - get current directory",
                "Usage: pwd [OPTIONS]",
                "  -? --help                show help"
        };
        Options opt = parseOptions(session, usage, argv);
        if (!opt.args().isEmpty()) {
            throw new IllegalArgumentException("usage: pwd");
        }
        process.out().println(session.currentDir());
    }

    protected void ls(CommandSession session, Process process, String[] argv) throws Exception {
        final String[] usage = {
                "ls - list files",
                "Usage: ls [OPTIONS] [PATTERNS...]",
                "  -? --help                show help",
                "  -1                       list one entry per line",
                "  -C                       multi-column output",
                "     --color=WHEN          colorize the output, may be `always', `never' or `auto'",
                "  -a                       list entries starting with .",
                "  -F                       append file type indicators",
                "  -m                       comma separated",
                "  -l                       long listing",
                "  -S                       sort by size",
                "  -f                       output is not sorted",
                "  -r                       reverse sort order",
                "  -t                       sort by modification time",
                "  -x                       sort horizontally",
                "  -L                       list referenced file for links",
                "  -h                       print sizes in human readable form"
        };
        Options opt = parseOptions(session, usage, argv);
        String color = opt.isSet("color") ? opt.get("color") : "auto";
        boolean colored;
        switch (color) {
            case "always":
            case "yes":
            case "force":
                colored = true;
                break;
            case "never":
            case "no":
            case "none":
                colored = false;
                break;
            case "auto":
            case "tty":
            case "if-tty":
                colored = process.isTty(1);
                break;
            default:
                throw new IllegalArgumentException("invalid argument ‘" + color + "’ for ‘--color’");
        }
        Map<String, String> colors = colored ? getLsColorMap(session) : Collections.emptyMap();

        class PathEntry implements Comparable<PathEntry> {
            final Path abs;
            final Path path;
            final Map<String, Object> attributes;

            public PathEntry(Path abs, Path root) {
                this.abs = abs;
                this.path = abs.startsWith(root) ? root.relativize(abs) : abs;
                this.attributes = readAttributes(abs);
            }

            @Override
            public int compareTo(PathEntry o) {
                int c = doCompare(o);
                return opt.isSet("r") ? -c : c;
            }

            private int doCompare(PathEntry o) {
                if (opt.isSet("f")) {
                    return -1;
                }
                if (opt.isSet("S")) {
                    long s0 = attributes.get("size") != null ? ((Number) attributes.get("size")).longValue() : 0L;
                    long s1 = o.attributes.get("size") != null ? ((Number) o.attributes.get("size")).longValue() : 0L;
                    return s0 > s1 ? -1 : s0 < s1 ? 1 : path.toString().compareTo(o.path.toString());
                }
                if (opt.isSet("t")) {
                    long t0 = attributes.get("lastModifiedTime") != null ? ((FileTime) attributes.get("lastModifiedTime")).toMillis() : 0L;
                    long t1 = o.attributes.get("lastModifiedTime") != null ? ((FileTime) o.attributes.get("lastModifiedTime")).toMillis() : 0L;
                    return t0 > t1 ? -1 : t0 < t1 ? 1 : path.toString().compareTo(o.path.toString());
                }
                return path.toString().compareTo(o.path.toString());
            }

            boolean isNotDirectory() {
                return is("isRegularFile") || is("isSymbolicLink") || is("isOther");
            }

            boolean isDirectory() {
                return is("isDirectory");
            }

            private boolean is(String attr) {
                Object d = attributes.get(attr);
                return d instanceof Boolean && (Boolean) d;
            }

            String display() {
                String type;
                String suffix;
                String link = "";
                if (is("isSymbolicLink")) {
                    type = "sl";
                    suffix = "@";
                    try {
                        Path l = Files.readSymbolicLink(abs);
                        link = " -> " + l.toString();
                    } catch (IOException e) {
                        // ignore
                    }
                } else if (is("isDirectory")) {
                    type = "dr";
                    suffix = "/";
                } else if (is("isExecutable")) {
                    type = "ex";
                    suffix = "*";
                } else if (is("isOther")) {
                    type = "ot";
                    suffix = "";
                } else {
                    type = "";
                    suffix = "";
                }
                String col = colors.get(type);
                boolean addSuffix = opt.isSet("F");
                if (col != null && !col.isEmpty()) {
                    return "\033[" + col + "m" + path.toString() + "\033[m" + (addSuffix ? suffix : "") + link;
                } else {
                    return path.toString() + (addSuffix ? suffix : "") + link;
                }
            }

            String longDisplay() {
                String username;
                if (attributes.containsKey("owner")) {
                    username = Objects.toString(attributes.get("owner"), null);
                } else {
                    username = "owner";
                }
                if (username.length() > 8) {
                    username = username.substring(0, 8);
                } else {
                    for (int i = username.length(); i < 8; i++) {
                        username = username + " ";
                    }
                }
                String group;
                if (attributes.containsKey("group")) {
                    group = Objects.toString(attributes.get("group"), null);
                } else {
                    group = "group";
                }
                if (group.length() > 8) {
                    group = group.substring(0, 8);
                } else {
                    for (int i = group.length(); i < 8; i++) {
                        group = group + " ";
                    }
                }
                Number length = (Number) attributes.get("size");
                if (length == null) {
                    length = 0L;
                }
                String lengthString;
                if (opt.isSet("h")) {
                    double l = length.longValue();
                    String unit = "B";
                    if (l >= 1000) {
                         l /= 1024;
                        unit = "K";
                        if (l >= 1000) {
                            l /= 1024;
                            unit = "M";
                            if (l >= 1000) {
                                l /= 1024;
                                unit = "T";
                            }
                        }
                    }
                    if (l < 10 && length.longValue() > 1000) {
                        lengthString = String.format("%.1f", l) + unit;
                    } else {
                        lengthString = String.format("%3.0f", l) + unit;
                    }
                } else {
                    lengthString = String.format("%1$8s", length);
                }
                @SuppressWarnings("unchecked")
                Set<PosixFilePermission> perms = (Set<PosixFilePermission>) attributes.get("permissions");
                if (perms == null) {
                    perms = EnumSet.noneOf(PosixFilePermission.class);
                }
                // TODO: all fields should be padded to align
                return (is("isDirectory") ? "d" : (is("isSymbolicLink") ? "l" : (is("isOther") ? "o" : "-")))
                        + PosixFilePermissions.toString(perms) + " "
                        + String.format("%3s", (attributes.containsKey("nlink") ? attributes.get("nlink").toString() : "1"))
                        + " " + username + " " + group + " " + lengthString + " "
                        + toString((FileTime) attributes.get("lastModifiedTime"))
                        + " " + display();
            }

            protected String toString(FileTime time) {
                long millis = (time != null) ? time.toMillis() : -1L;
                if (millis < 0L) {
                    return "------------";
                }
                ZonedDateTime dt = Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault());
                // Less than six months
                if (System.currentTimeMillis() - millis < 183L * 24L * 60L * 60L * 1000L) {
                    return DateTimeFormatter.ofPattern("MMM ppd HH:mm").format(dt);
                }
                // Older than six months
                else {
                    return DateTimeFormatter.ofPattern("MMM ppd  yyyy").format(dt);
                }
            }

            protected Map<String, Object> readAttributes(Path path) {
                Map<String, Object>  attrs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                for (String view : path.getFileSystem().supportedFileAttributeViews()) {
                    try {
                        Map<String, Object> ta = Files.readAttributes(path, view + ":*",
                                getLinkOptions(opt.isSet("L")));
                        ta.entrySet().forEach(e -> attrs.putIfAbsent(e.getKey(), e.getValue()));
                    } catch (IOException e) {
                        // Ignore
                    }
                }
                attrs.computeIfAbsent("isExecutable", s -> Files.isExecutable(path));
                attrs.computeIfAbsent("permissions", s -> getPermissionsFromFile(path.toFile()));
                return attrs;
            }
        }

        Path currentDir = session.currentDir();
        // Listing
        List<Path> expanded = new ArrayList<>();
        if (opt.args().isEmpty()) {
            expanded.add(currentDir);
        } else {
            opt.args().forEach(s -> expanded.add(currentDir.resolve(s)));
        }
        boolean listAll = opt.isSet("a");
        Predicate<Path> filter = p -> listAll || !p.getFileName().toString().startsWith(".");
        List<PathEntry> all = expanded.stream()
                .filter(filter)
                .map(p -> new PathEntry(p, currentDir))
                .sorted()
                .collect(Collectors.toList());
        // Print files first
        List<PathEntry> files = all.stream()
                .filter(PathEntry::isNotDirectory)
                .collect(Collectors.toList());
        PrintStream out = process.out();
        Consumer<Stream<PathEntry>> display = s -> {
            boolean optLine  = opt.isSet("1");
            boolean optComma = opt.isSet("m");
            boolean optLong  = opt.isSet("l");
            boolean optCol   = opt.isSet("C");
            if (!optLine && !optComma && !optLong && !optCol) {
                if (process.isTty(1)) {
                    optCol = true;
                }
                else {
                    optLine = true;
                }
            }
            // One entry per line
            if (optLine) {
                s.map(PathEntry::display).forEach(out::println);
            }
            // Comma separated list
            else if (optComma) {
                out.println(s.map(PathEntry::display).collect(Collectors.joining(", ")));
            }
            // Long listing
            else if (optLong) {
                s.map(PathEntry::longDisplay).forEach(out::println);
            }
            // Column listing
            else if (optCol) {
                toColumn(session, process, out, s.map(PathEntry::display), opt.isSet("x"));
            }
        };
        boolean space = false;
        if (!files.isEmpty()) {
            display.accept(files.stream());
            space = true;
        }
        // Print directories
        List<PathEntry> directories = all.stream()
                .filter(PathEntry::isDirectory)
                .collect(Collectors.toList());
        for (PathEntry entry : directories) {
            if (space) {
                out.println();
            }
            space = true;
            Path path = currentDir.resolve(entry.path);
            if (expanded.size() > 1) {
                out.println(currentDir.relativize(path).toString() + ":");
            }
            display.accept(Stream.concat(Arrays.asList(".", "..").stream().map(path::resolve), Files.list(path))
                            .filter(filter)
                            .map(p -> new PathEntry(p, path))
                            .sorted()
            );
        }
    }

    private void toColumn(CommandSession session, Process process, PrintStream out, Stream<String> ansi, boolean horizontal) {
        Terminal terminal = Shell.getTerminal(session);
        int width = process.isTty(1) ? terminal.getWidth() : 80;
        List<AttributedString> strings = ansi.map(AttributedString::fromAnsi).collect(Collectors.toList());
        if (!strings.isEmpty()) {
            int max = strings.stream().mapToInt(AttributedString::columnLength).max().getAsInt();
            int c = Math.max(1, width / max);
            while (c > 1 && c * max + (c - 1) >= width) {
                c--;
            }
            int columns = c;
            int lines = (strings.size() + columns - 1) / columns;
            IntBinaryOperator index;
            if (horizontal) {
                index = (i, j) -> i * columns + j;
            } else {
                index = (i, j) -> j * lines + i;
            }
            AttributedStringBuilder sb = new AttributedStringBuilder();
            for (int i = 0; i < lines; i++) {
                for (int j = 0; j < columns; j++) {
                    int idx = index.applyAsInt(i, j);
                    if (idx < strings.size()) {
                        AttributedString str = strings.get(idx);
                        boolean hasRightItem = j < columns - 1 && index.applyAsInt(i, j + 1) < strings.size();
                        sb.append(str);
                        if (hasRightItem) {
                            for (int k = 0; k <= max - str.length(); k++) {
                                sb.append(' ');
                            }
                        }
                    }
                }
                sb.append('\n');
            }
            out.print(sb.toAnsi(terminal));
        }
    }

    protected void cat(CommandSession session, Process process, String[] argv) throws Exception {
        final String[] usage = {
                "cat - concatenate and print FILES",
                "Usage: cat [OPTIONS] [FILES]",
                "  -? --help                show help",
                "  -n                       number the output lines, starting at 1"
        };
        Options opt = parseOptions(session, usage, argv);
        List<String> args = opt.args();
        if (args.isEmpty()) {
            args = Collections.singletonList("-");
        }
        Path cwd = session.currentDir();
        for (String arg : args) {
            InputStream is;
            if ("-".equals(arg)) {
                is = process.in();
            } else {
                is = cwd.toUri().resolve(arg).toURL().openStream();
            }
            cat(process, new BufferedReader(new InputStreamReader(is)), opt.isSet("n"));
        }
    }

    protected static void read(BufferedReader r, List<String> lines) throws IOException {
        for (String s = r.readLine(); s != null; s = r.readLine()) {
            lines.add(s);
        }
    }

    private static void cat(Process process, final BufferedReader reader, boolean displayLineNumbers) throws IOException {
        String line;
        int lineno = 1;
        try {
            while ((line = reader.readLine()) != null) {
                if (displayLineNumbers) {
                    process.out().print(String.format("%6d  ", lineno++));
                }
                process.out().println(line);
            }
        } finally {
            reader.close();
        }
    }

    public static class SortComparator implements Comparator<String> {

        private static Pattern fpPattern;

        static {
            final String Digits = "(\\p{Digit}+)";
            final String HexDigits = "(\\p{XDigit}+)";
            final String Exp = "[eE][+-]?" + Digits;
            final String fpRegex = "([\\x00-\\x20]*[+-]?(NaN|Infinity|(((" + Digits + "(\\.)?(" + Digits + "?)(" + Exp + ")?)|(\\.(" + Digits + ")(" + Exp + ")?)|(((0[xX]" + HexDigits + "(\\.)?)|(0[xX]" + HexDigits + "?(\\.)" + HexDigits + "))[pP][+-]?" + Digits + "))" + "[fFdD]?))[\\x00-\\x20]*)(.*)";
            fpPattern = Pattern.compile(fpRegex);
        }

        private boolean caseInsensitive;
        private boolean reverse;
        private boolean ignoreBlanks;
        private boolean numeric;
        private char separator;
        private List<Key> sortKeys;

        public SortComparator(boolean caseInsensitive,
                              boolean reverse,
                              boolean ignoreBlanks,
                              boolean numeric,
                              char separator,
                              List<String> sortFields) {
            this.caseInsensitive = caseInsensitive;
            this.reverse = reverse;
            this.separator = separator;
            this.ignoreBlanks = ignoreBlanks;
            this.numeric = numeric;
            if (sortFields == null || sortFields.size() == 0) {
                sortFields = new ArrayList<>();
                sortFields.add("1");
            }
            sortKeys = sortFields.stream().map(Key::new).collect(Collectors.toList());
        }

        public int compare(String o1, String o2) {
            int res = 0;

            List<Integer> fi1 = getFieldIndexes(o1);
            List<Integer> fi2 = getFieldIndexes(o2);
            for (Key key : sortKeys) {
                int[] k1 = getSortKey(o1, fi1, key);
                int[] k2 = getSortKey(o2, fi2, key);
                if (key.numeric) {
                    Double d1 = getDouble(o1, k1[0], k1[1]);
                    Double d2 = getDouble(o2, k2[0], k2[1]);
                    res = d1.compareTo(d2);
                } else {
                    res = compareRegion(o1, k1[0], k1[1], o2, k2[0], k2[1], key.caseInsensitive);
                }
                if (res != 0) {
                    if (key.reverse) {
                        res = -res;
                    }
                    break;
                }
            }
            return res;
        }

        protected Double getDouble(String s, int start, int end) {
            Matcher m = fpPattern.matcher(s.substring(start, end));
            m.find();
            return new Double(s.substring(0, m.end(1)));
        }

        protected int compareRegion(String s1, int start1, int end1, String s2, int start2, int end2, boolean caseInsensitive) {
            for (int i1 = start1, i2 = start2; i1 < end1 && i2 < end2; i1++, i2++) {
                char c1 = s1.charAt(i1);
                char c2 = s2.charAt(i2);
                if (c1 != c2) {
                    if (caseInsensitive) {
                        c1 = Character.toUpperCase(c1);
                        c2 = Character.toUpperCase(c2);
                        if (c1 != c2) {
                            c1 = Character.toLowerCase(c1);
                            c2 = Character.toLowerCase(c2);
                            if (c1 != c2) {
                                return c1 - c2;
                            }
                        }
                    } else {
                        return c1 - c2;
                    }
                }
            }
            return end1 - end2;
        }

        protected int[] getSortKey(String str, List<Integer> fields, Key key) {
            int start;
            int end;
            if (key.startField * 2 <= fields.size()) {
                start = fields.get((key.startField - 1) * 2);
                if (key.ignoreBlanksStart) {
                    while (start < fields.get((key.startField - 1) * 2 + 1) && Character.isWhitespace(str.charAt(start))) {
                        start++;
                    }
                }
                if (key.startChar > 0) {
                    start = Math.min(start + key.startChar - 1, fields.get((key.startField - 1) * 2 + 1));
                }
            } else {
                start = 0;
            }
            if (key.endField > 0 && key.endField * 2 <= fields.size()) {
                end = fields.get((key.endField - 1) * 2);
                if (key.ignoreBlanksEnd) {
                    while (end < fields.get((key.endField - 1) * 2 + 1) && Character.isWhitespace(str.charAt(end))) {
                        end++;
                    }
                }
                if (key.endChar > 0) {
                    end = Math.min(end + key.endChar - 1, fields.get((key.endField - 1) * 2 + 1));
                }
            } else {
                end = str.length();
            }
            return new int[]{start, end};
        }

        protected List<Integer> getFieldIndexes(String o) {
            List<Integer> fields = new ArrayList<>();
            if (o.length() > 0) {
                if (separator == '\0') {
                    fields.add(0);
                    for (int idx = 1; idx < o.length(); idx++) {
                        if (Character.isWhitespace(o.charAt(idx)) && !Character.isWhitespace(o.charAt(idx - 1))) {
                            fields.add(idx - 1);
                            fields.add(idx);
                        }
                    }
                    fields.add(o.length() - 1);
                } else {
                    int last = -1;
                    for (int idx = o.indexOf(separator); idx >= 0; idx = o.indexOf(separator, idx + 1)) {
                        if (last >= 0) {
                            fields.add(last);
                            fields.add(idx - 1);
                        } else if (idx > 0) {
                            fields.add(0);
                            fields.add(idx - 1);
                        }
                        last = idx + 1;
                    }
                    if (last < o.length()) {
                        fields.add(last < 0 ? 0 : last);
                        fields.add(o.length() - 1);
                    }
                }
            }
            return fields;
        }

        public class Key {
            int startField;
            int startChar;
            int endField;
            int endChar;
            boolean ignoreBlanksStart;
            boolean ignoreBlanksEnd;
            boolean caseInsensitive;
            boolean reverse;
            boolean numeric;

            public Key(String str) {
                boolean modifiers = false;
                boolean startPart = true;
                boolean inField = true;
                boolean inChar = false;
                for (char c : str.toCharArray()) {
                    switch (c) {
                        case '0':
                        case '1':
                        case '2':
                        case '3':
                        case '4':
                        case '5':
                        case '6':
                        case '7':
                        case '8':
                        case '9':
                            if (!inField && !inChar) {
                                throw new IllegalArgumentException("Bad field syntax: " + str);
                            }
                            if (startPart) {
                                if (inChar) {
                                    startChar = startChar * 10 + (c - '0');
                                } else {
                                    startField = startField * 10 + (c - '0');
                                }
                            } else {
                                if (inChar) {
                                    endChar = endChar * 10 + (c - '0');
                                } else {
                                    endField = endField * 10 + (c - '0');
                                }
                            }
                            break;
                        case '.':
                            if (!inField) {
                                throw new IllegalArgumentException("Bad field syntax: " + str);
                            }
                            inField = false;
                            inChar = true;
                            break;
                        case 'n':
                            inField = false;
                            inChar = false;
                            modifiers = true;
                            numeric = true;
                            break;
                        case 'f':
                            inField = false;
                            inChar = false;
                            modifiers = true;
                            caseInsensitive = true;
                            break;
                        case 'r':
                            inField = false;
                            inChar = false;
                            modifiers = true;
                            reverse = true;
                            break;
                        case 'b':
                            inField = false;
                            inChar = false;
                            modifiers = true;
                            if (startPart) {
                                ignoreBlanksStart = true;
                            } else {
                                ignoreBlanksEnd = true;
                            }
                            break;
                        case ',':
                            inField = true;
                            inChar = false;
                            startPart = false;
                            break;
                        default:
                            throw new IllegalArgumentException("Bad field syntax: " + str);
                    }
                }
                if (!modifiers) {
                    ignoreBlanksStart = ignoreBlanksEnd = SortComparator.this.ignoreBlanks;
                    reverse = SortComparator.this.reverse;
                    caseInsensitive = SortComparator.this.caseInsensitive;
                    numeric = SortComparator.this.numeric;
                }
                if (startField < 1) {
                    throw new IllegalArgumentException("Bad field syntax: " + str);
                }
            }
        }
    }

    private static LinkOption[] getLinkOptions(boolean followLinks) {
        if (followLinks) {
            return EMPTY_LINK_OPTIONS;
        } else {    // return a clone that modifications to the array will not affect others
            return NO_FOLLOW_OPTIONS.clone();
        }
    }

    /**
     * @param fileName The file name to be evaluated - ignored if {@code null}/empty
     * @return {@code true} if the file ends in one of the {@link #WINDOWS_EXECUTABLE_EXTENSIONS}
     */
    private static boolean isWindowsExecutable(String fileName) {
        if ((fileName == null) || (fileName.length() <= 0)) {
            return false;
        }
        for (String suffix : WINDOWS_EXECUTABLE_EXTENSIONS) {
            if (fileName.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param f The {@link File} to be checked
     * @return A {@link Set} of {@link PosixFilePermission}s based on whether
     * the file is readable/writable/executable. If so, then <U>all</U> the
     * relevant permissions are set (i.e., owner, group and others)
     */
    private static Set<PosixFilePermission> getPermissionsFromFile(File f) {
        Set<PosixFilePermission> perms = EnumSet.noneOf(PosixFilePermission.class);
        if (f.canRead()) {
            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.GROUP_READ);
            perms.add(PosixFilePermission.OTHERS_READ);
        }

        if (f.canWrite()) {
            perms.add(PosixFilePermission.OWNER_WRITE);
            perms.add(PosixFilePermission.GROUP_WRITE);
            perms.add(PosixFilePermission.OTHERS_WRITE);
        }

        if (f.canExecute() || (OSUtils.IS_WINDOWS && isWindowsExecutable(f.getName()))) {
            perms.add(PosixFilePermission.OWNER_EXECUTE);
            perms.add(PosixFilePermission.GROUP_EXECUTE);
            perms.add(PosixFilePermission.OTHERS_EXECUTE);
        }

        return perms;
    }

    public static Map<String, String> getLsColorMap(CommandSession session) {
        return getColorMap(session, "LS", DEFAULT_LS_COLORS);
    }

    public static Map<String, String> getColorMap(CommandSession session, String name, String def) {
        Object obj = session.get(name + "_COLORS");
        String str = obj != null ? obj.toString() : null;
        if (str == null || !str.matches("[a-z]{2}=[0-9]*(;[0-9]+)*(:[a-z]{2}=[0-9]*(;[0-9]+)*)*")) {
            str = def;
        }
        return Arrays.stream(str.split(":"))
                .collect(Collectors.toMap(s -> s.substring(0, s.indexOf('=')),
                                          s -> s.substring(s.indexOf('=') + 1)));
    }

    private void applyStyle(AttributedStringBuilder sb, Map<String, String> colors, String... types) {
        String col = null;
        for (String type : types) {
            col = colors.get(type);
            if (col != null) {
                break;
            }
        }
        sb.style(AttributedStyle.DEFAULT);
        if (col != null && !col.isEmpty()) {
            sb.appendAnsi("\033[" + col + "m");
        }
    }

}
