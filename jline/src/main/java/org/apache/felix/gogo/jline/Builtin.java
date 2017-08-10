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
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.felix.service.command.Job;
import org.apache.felix.service.command.Process;
import org.apache.felix.gogo.runtime.CommandSessionImpl;
import org.apache.felix.service.command.CommandSession;
import org.apache.felix.service.command.Converter;
import org.apache.felix.service.command.Function;
import org.jline.builtins.Commands;
import org.jline.builtins.Completers.DirectoriesCompleter;
import org.jline.builtins.Completers.FilesCompleter;
import org.jline.builtins.Options;
import org.jline.reader.Candidate;
import org.jline.reader.LineReader;
import org.jline.reader.ParsedLine;
import org.jline.reader.Widget;
import org.jline.terminal.Terminal;

import static org.apache.felix.gogo.jline.Shell.getCommands;

/**
 * gosh built-in commands.
 */
public class Builtin {

    static final String[] functions = {
            "format", "getopt", "new", "set",
            "keymap", "setopt", "unsetopt", "complete", "history", "widget",
            "__files", "__directories", "__usage_completion"
    };

    private static final String[] packages = {"java.lang", "java.io", "java.net", "java.util"};

    private final static Set<String> KEYWORDS = new HashSet<String>(
            Arrays.asList(new String[]{"abstract", "continue", "for", "new", "switch",
                    "assert", "default", "goto", "package", "synchronized", "boolean", "do",
                    "if", "private", "this", "break", "double", "implements", "protected",
                    "throw", "byte", "else", "import", "public", "throws", "case", "enum",
                    "instanceof", "return", "transient", "catch", "extends", "int", "short",
                    "try", "char", "final", "interface", "static", "void", "class",
                    "finally", "long", "strictfp", "volatile", "const", "float", "native",
                    "super", "while"}));

    public CharSequence format(CommandSession session) {
        return format(session, session.get("_"));    // last result
    }

    public CharSequence format(CommandSession session, Object arg) {
        Process process = Process.Utils.current();
        CharSequence result = session.format(arg, Converter.INSPECT);
        process.out().println(result);
        return result;
    }

    /**
     * script access to Options.
     */
    public Options getopt(List<Object> spec, Object[] args) {
        String[] optSpec = new String[spec.size()];
        for (int i = 0; i < optSpec.length; ++i) {
            optSpec[i] = spec.get(i).toString();
        }
        return Options.compile(optSpec).parse(args);
    }

    // FIXME: the "new" command should be provided by runtime,
    // so it can leverage same argument coercion mechanism, used to invoke methods.
    public Object _new(CommandSession session, Object name, Object[] argv) throws Exception {
        Class<?> clazz;

        if (name instanceof Class<?>) {
            clazz = (Class<?>) name;
        } else {
            clazz = loadClass(name.toString());
        }

        for (Constructor<?> c : clazz.getConstructors()) {
            Class<?>[] types = c.getParameterTypes();
            if (types.length != argv.length) {
                continue;
            }

            boolean match = true;

            Object[] transformed = argv.clone();
            for (int i = 0; i < transformed.length; ++i) {
                try {
                    transformed[i] = session.convert(types[i], transformed[i]);
                } catch (IllegalArgumentException e) {
                    match = false;
                    break;
                }
            }

            if (!match) {
                continue;
            }

            try {
                return c.newInstance(transformed);
            } catch (InvocationTargetException ite) {
                Throwable cause = ite.getCause();
                if (cause instanceof Exception) {
                    throw (Exception) cause;
                }
                throw ite;
            }
        }

        throw new IllegalArgumentException("can't coerce " + Arrays.asList(argv)
                + " to any of " + Arrays.asList(clazz.getConstructors()));
    }

    private Class<?> loadClass(String name) throws ClassNotFoundException {
        if (!name.contains(".")) {
            for (String p : packages) {
                String pkg = p + "." + name;
                try {
                    return Class.forName(pkg);
                } catch (ClassNotFoundException e) {
                }
            }
        }
        return Class.forName(name);
    }

    public void set(CommandSession session, String[] argv) throws Exception {
        final String[] usage = {
                "set - show session variables",
                "Usage: set [OPTIONS] [PREFIX]",
                "  -? --help                show help",
                "  -a --all                 show all variables, including those starting with .",
                "  -x                       set xtrace option",
                "  +x                       unset xtrace option",
                "If PREFIX given, then only show variable(s) starting with PREFIX"};

        Process process = Process.Utils.current();
        Options opt = Options.compile(usage).parse(argv);

        if (opt.isSet("help")) {
            opt.usage(process.err());
            return;
        }

        List<String> args = opt.args();
        String prefix = (args.isEmpty() ? "" : args.get(0));

        if (opt.isSet("x")) {
            session.put("echo", true);
        } else if ("+x".equals(prefix)) {
            session.put("echo", null);
        } else {
            boolean all = opt.isSet("all");
            for (String key : new TreeSet<String>(Shell.getVariables(session))) {
                if (!key.startsWith(prefix))
                    continue;

                if (key.startsWith(".") && !(all || prefix.length() > 0))
                    continue;

                Object target = session.get(key);
                String type = null;
                String value = null;

                if (target != null) {
                    Class<? extends Object> clazz = target.getClass();
                    type = clazz.getSimpleName();
                    value = target.toString();
                }

                String trunc = value == null || value.length() < 55 ? "" : "...";
                process.out().println(String.format("%-15.15s %-15s %.45s%s", type, key,
                        value, trunc));
            }
        }
    }

    /*
     * the following methods depend on the internals of the runtime implementation.
     * ideally, they should be available via some API.
     */

    private boolean isClosure(Object target) {
        return target.getClass().getSimpleName().equals("Closure");
    }

    private boolean isCommand(Object target) {
        return target.getClass().getSimpleName().equals("CommandProxy");
    }

    private CharSequence getClosureSource(CommandSession session, String name)
            throws Exception {
        Object target = session.get(name);

        if (target == null) {
            return null;
        }

        if (!isClosure(target)) {
            return null;
        }

        Field sourceField = target.getClass().getDeclaredField("source");
        sourceField.setAccessible(true);
        return (CharSequence) sourceField.get(target);
    }

    private List<Method> getMethods(CommandSession session, String scmd) throws Exception {
        final int colon = scmd.indexOf(':');
        final String function = colon == -1 ? scmd : scmd.substring(colon + 1);
        final String name = KEYWORDS.contains(function) ? ("_" + function) : function;
        final String get = "get" + function;
        final String is = "is" + function;
        final String set = "set" + function;
        final String MAIN = "_main"; // FIXME: must match Reflective.java

        Object target = session.get(scmd);
        if (target == null) {
            return null;
        }

        if (isClosure(target)) {
            return null;
        }

        if (isCommand(target)) {
            Method method = target.getClass().getMethod("getTarget", (Class[]) null);
            method.setAccessible(true);
            target = method.invoke(target, (Object[]) null);
        }

        ArrayList<Method> list = new ArrayList<Method>();
        Class<?> tc = (target instanceof Class<?>) ? (Class<?>) target
                : target.getClass();
        Method[] methods = tc.getMethods();

        for (Method m : methods) {
            String mname = m.getName().toLowerCase();

            if (mname.equals(name) || mname.equals(get) || mname.equals(set)
                    || mname.equals(is) || mname.equals(MAIN)) {
                list.add(m);
            }
        }

        return list;
    }

    public void history(CommandSession session, String[] argv) throws IOException {
        Process process = Process.Utils.current();
        Commands.history(Shell.getReader(session), process.out(), process.err(), argv);
    }

    public void complete(CommandSession session, String[] argv) {
        Process process = Process.Utils.current();
        Commands.complete(Shell.getReader(session), process.out(), process.err(), Shell.getCompletions(session), argv);
    }

    public void widget(final CommandSession session, String[] argv) throws Exception {
        java.util.function.Function<String, Widget> creator = func -> () -> {
            try {
                session.execute(func);
            } catch (Exception e) {
                // TODO: log exception ?
                return false;
            }
            return true;
        };
        Process process = Process.Utils.current();
        Commands.widget(Shell.getReader(session), process.out(), process.err(), creator, argv);
    }

    public void keymap(CommandSession session, String[] argv) {
        Process process = Process.Utils.current();
        Commands.keymap(Shell.getReader(session), process.out(), process.err(), argv);
    }

    public void setopt(CommandSession session, String[] argv) {
        Process process = Process.Utils.current();
        Commands.setopt(Shell.getReader(session), process.out(), process.err(), argv);
    }

    public void unsetopt(CommandSession session, String[] argv) {
        Process process = Process.Utils.current();
        Commands.unsetopt(Shell.getReader(session), process.out(), process.err(), argv);
    }

    public List<Candidate> __files(CommandSession session) {
        ParsedLine line = Shell.getParsedLine(session);
        LineReader reader = Shell.getReader(session);
        List<Candidate> candidates = new ArrayList<>();
        new FilesCompleter(session.currentDir()) {
            @Override
            protected String getDisplay(Terminal terminal, Path p) {
                return getFileDisplay(session, p);
            }
        }.complete(reader, line, candidates);
        return candidates;
    }

    public List<Candidate> __directories(CommandSession session) {
        ParsedLine line = Shell.getParsedLine(session);
        LineReader reader = Shell.getReader(session);
        List<Candidate> candidates = new ArrayList<>();
        new DirectoriesCompleter(session.currentDir()) {
            @Override
            protected String getDisplay(Terminal terminal, Path p) {
                return getFileDisplay(session, p);
            }
        }.complete(reader, line, candidates);
        return candidates;
    }

    private String getFileDisplay(CommandSession session, Path path) {
        String type;
        String suffix;
        if (Files.isSymbolicLink(path)) {
            type = "sl";
            suffix = "@";
        } else if (Files.isDirectory(path)) {
            type = "dr";
            suffix = "/";
        } else if (Files.isExecutable(path)) {
            type = "ex";
            suffix = "*";
        } else if (!Files.isRegularFile(path)) {
            type = "ot";
            suffix = "";
        } else {
            type = "";
            suffix = "";
        }
        String col = Posix.getLsColorMap(session).get(type);
        if (col != null && !col.isEmpty()) {
            return "\033[" + col + "m" + path.getFileName().toString() + "\033[m" + suffix;
        } else {
            return path.getFileName().toString() + suffix;
        }

    }

    public void __usage_completion(CommandSession session, String command) throws Exception {
        Object func = session.get(command.contains(":") ? command : "*:" + command);
        if (func instanceof Function) {
            ByteArrayInputStream bais = new ByteArrayInputStream(new byte[0]);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ByteArrayOutputStream baes = new ByteArrayOutputStream();
            CommandSession ts = ((CommandSessionImpl) session).processor().createSession(bais, new PrintStream(baos), new PrintStream(baes));
            ts.execute(command + " --help");

            String regex = "(?x)\\s*" + "(?:-([^-]))?" +  // 1: short-opt-1
                    "(?:,?\\s*-(\\w))?" +                 // 2: short-opt-2
                    "(?:,?\\s*--(\\w[\\w-]*)(=\\w+)?)?" + // 3: long-opt-1 and 4:arg-1
                    "(?:,?\\s*--(\\w[\\w-]*))?" +         // 5: long-opt-2
                    ".*?(?:\\(default=(.*)\\))?\\s*" +    // 6: default
                    "(.*)";                               // 7: description
            Pattern pattern = Pattern.compile(regex);
            for (String l : baes.toString().split("\n")) {
                Matcher matcher = pattern.matcher(l);
                if (matcher.matches()) {
                    List<String> args = new ArrayList<>();
                    if (matcher.group(1) != null) {
                        args.add("--short-option");
                        args.add(matcher.group(1));
                    }
                    if (matcher.group(3) != null) {
                        args.add("--long-option");
                        args.add(matcher.group(1));
                    }
                    if (matcher.group(4) != null) {
                        args.add("--argument");
                        args.add("");
                    }
                    if (matcher.group(7) != null) {
                        args.add("--description");
                        args.add(matcher.group(7));
                    }
                    complete(session, args.toArray(new String[args.size()]));
                }
            }
        }
    }
}
