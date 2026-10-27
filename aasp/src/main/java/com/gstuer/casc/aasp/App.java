package com.gstuer.casc.aasp;

import com.gstuer.casc.common.cryptography.Authenticator;
import com.gstuer.casc.common.cryptography.AuthenticatorFactory;
import com.gstuer.casc.common.egress.AccessControlMessageEgressHandler;
import com.gstuer.casc.common.ingress.AccessControlMessageIngressHandler;
import com.gstuer.casc.common.message.AccessControlMessage;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

public class App {
    private static final int UDP_PORT_INCOMING = 10000;
    private static final int UDP_PORT_OUTGOING = 10001;

    public static void main(String[] args) {
        System.out.println("AASP - Attribute Administration & Storage Point");

        // Configure SLF4J logging verbosity
        System.setProperty("slf4j.internal.verbosity", "WARN");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "WARN");

        // Parse command line arguments without required options to avoid help dialog not being printed in case of missing arguments
        CommandLine commandLine;
        try {
            commandLine = parseCommandLine(args, false);
        } catch (ParseException exception) {
            System.err.println(exception.getMessage());
            return;
        }

        // Print help dialog if requested by user
        if (commandLine.hasOption("h")) {
            displayHelp();
            return;
        }

        // Parse command line arguments with required options
        try {
            commandLine = parseCommandLine(args, true);
        } catch (ParseException exception) {
            System.err.println(exception.getMessage());
            return;
        }

        // Parse authentication authority (KGC) address from command line arguments
        InetAddress authenticationAuthority;
        String authenticationAuthorityHostname = commandLine.getOptionValue("authentication");
        try {
            authenticationAuthority = InetAddress.getByName(authenticationAuthorityHostname);
        } catch (UnknownHostException exception) {
            System.err.println("Resolving authentication authority hostname failed: " + exception.getMessage());
            return;
        }

        // Parse the address at which the PDPs reach this AASP, which identifies the attributes it publishes
        InetAddress provider;
        try {
            provider = InetAddress.getByName(commandLine.getOptionValue("provider"));
        } catch (UnknownHostException exception) {
            System.err.println("Resolving provider hostname failed: " + exception.getMessage());
            return;
        }

        // Parse authenticator from command line arguments
        Optional<Authenticator<?, ?>> optionalAuthenticator = AuthenticatorFactory.createByIdentifier(commandLine.getOptionValue("crypto"));
        if (optionalAuthenticator.isEmpty()) {
            System.err.println("Parsing cryptographic algorithm failed: Unknown algorithm.");
            return;
        }
        Authenticator<?, ?> authenticator = optionalAuthenticator.get();

        // Read the configuration of the attributes to be published
        AttributeConfiguration configuration;
        try {
            configuration = AttributeConfiguration.readFrom(Path.of(commandLine.getOptionValue("attributes")));
        } catch (IOException exception) {
            System.err.println("Reading the attribute configuration failed: " + exception.getMessage());
            return;
        } catch (IllegalArgumentException exception) {
            System.err.println("Parsing the attribute configuration failed: " + exception.getMessage());
            return;
        }

        // Construct controller, which publishes the configured attributes
        BlockingQueue<AccessControlMessage<?>> egressQueue = new LinkedBlockingQueue<>();
        AttributeController controller;
        try {
            controller = new AttributeController(egressQueue, authenticationAuthority, authenticator, provider,
                    configuration);
        } catch (IllegalArgumentException | IllegalStateException exception) {
            System.err.println("Publishing the configured attributes failed: " + exception.getMessage());
            return;
        }

        // Construct ingress and egress handlers
        AccessControlMessageEgressHandler egressHandler = new AccessControlMessageEgressHandler(UDP_PORT_OUTGOING, UDP_PORT_INCOMING, egressQueue);
        AccessControlMessageIngressHandler ingressHandler = new AccessControlMessageIngressHandler(UDP_PORT_INCOMING, controller::handleRequest);

        // Start handler threads
        ExecutorService threadPool = Executors.newFixedThreadPool(2);
        threadPool.submit(() -> runHandler("egress", egressHandler::open));
        threadPool.submit(() -> runHandler("ingress", ingressHandler::open));
    }

    /**
     * Runs a message handler and reports its failure, so that an AASP which stopped communicating does not look
     * like one that is idle: a handler submitted to an executor service would otherwise fail silently, as nothing
     * inspects the result of its execution.
     *
     * @param name    the name of the handler, as it appears in the failure message
     * @param handler the handler to be run
     */
    private static void runHandler(String name, Runnable handler) {
        try {
            handler.run();
        } catch (RuntimeException | Error throwable) {
            System.err.printf("[AASP] The %s handler stopped: %s\n", name, throwable);
            throwable.printStackTrace();
        }
    }

    private static CommandLine parseCommandLine(String[] args, boolean parseWithRequiredOptions) throws ParseException {
        CommandLineParser parser = new DefaultParser(false);
        return parser.parse(getCommandLineOptions(parseWithRequiredOptions), args, false);
    }

    private static void displayHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("app", getCommandLineOptions(true), true);
    }

    private static Options getCommandLineOptions(boolean enableRequiredOptions) {
        Options options = new Options();
        options.addOption(Option.builder()
                .longOpt("authentication")
                .desc("set the hostname or address of the authentication authority")
                .numberOfArgs(1)
                .argName("hostname")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder()
                .longOpt("crypto")
                .desc("set the cryptographic algorithm used for authentication")
                .numberOfArgs(1)
                .argName("algorithm")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder()
                .longOpt("provider")
                .desc("set the hostname or address at which the PDPs reach this AASP, which identifies the attributes"
                        + " it publishes together with their names")
                .numberOfArgs(1)
                .argName("hostname")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder()
                .longOpt("attributes")
                .desc("set the path of the JSON document configuring the attributes to be published")
                .numberOfArgs(1)
                .argName("path")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder("h")
                .longOpt("help")
                .desc("displays usage information of the program and exit")
                .build());
        return options;
    }
}
