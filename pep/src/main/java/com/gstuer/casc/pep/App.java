package com.gstuer.casc.pep;

import com.gstuer.casc.common.cryptography.Authenticator;
import com.gstuer.casc.common.cryptography.AuthenticatorFactory;
import com.gstuer.casc.pep.forwarding.ForwardingBridge;
import com.gstuer.casc.pep.predicate.ArpPredicate;
import com.gstuer.casc.pep.predicate.IcmpV4Predicate;
import com.gstuer.casc.pep.predicate.LldpPredicate;
import com.gstuer.casc.pep.predicate.PrpPredicate;
import com.gstuer.casc.pep.predicate.PtpPredicate;
import com.gstuer.casc.pep.predicate.SshOverTcpPredicate;
import com.gstuer.casc.pep.predicate.StpPredicate;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.LinkLayerAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Optional;

public class App {
    private static final String VERIFICATION_AUTHORITY_NONE = "none";

    public static void main(String[] args) {
        System.out.println("IP/PEP - Intrusion Prevention & Policy Enforcement Point");

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

        // Print list of network interfaces if requested by user
        if (commandLine.hasOption("l")) {
            try {
                displayInterfaceList();
            } catch (PcapNativeException exception) {
                System.err.println("Listing network interfaces failed: " + exception.getMessage());
                return;
            }
        }

        // Parse command line arguments with required options
        try {
            commandLine = parseCommandLine(args, true);
        } catch (ParseException exception) {
            System.err.println(exception.getMessage());
            return;
        }

        // Parse interface identifiers from command line arguments and create pcap interfaces
        PcapNetworkInterface secureNetworkInterface;
        PcapNetworkInterface insecureNetworkInterface;
        String secureInterfaceIdentifier = commandLine.getOptionValue("s");
        String insecureInterfaceIdentifier = commandLine.getOptionValue("i");
        try {
            secureNetworkInterface = Pcaps.getDevByName(secureInterfaceIdentifier);
            insecureNetworkInterface = Pcaps.getDevByName(insecureInterfaceIdentifier);
        } catch (PcapNativeException exception) {
            System.err.println("Setting up interfaces failed: " + exception.getMessage());
            return;
        }

        // Parse authorization authority (PDP) address from command line arguments
        InetAddress authorizationAuthority;
        String authorizationAuthorityHostname = commandLine.getOptionValue("authorization");
        try {
            authorizationAuthority = InetAddress.getByName(authorizationAuthorityHostname);
        } catch (UnknownHostException exception) {
            System.err.println("Resolving authorization authority hostname failed: " + exception.getMessage());
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

        // Parse the addresses of the PDPs used for the optional server-aided access decision verification
        InetAddress incomingVerificationAuthority = null;
        InetAddress outgoingVerificationAuthority = null;
        if (commandLine.hasOption("decision-verification")) {
            String[] verificationAuthorityHostnames = commandLine.getOptionValues("decision-verification");
            if (verificationAuthorityHostnames.length != 2) {
                System.err.println("Parsing decision verification authorities failed: Two values are required.");
                return;
            }
            try {
                incomingVerificationAuthority = resolveVerificationAuthority(verificationAuthorityHostnames[0]);
                outgoingVerificationAuthority = resolveVerificationAuthority(verificationAuthorityHostnames[1]);
            } catch (UnknownHostException exception) {
                System.err.println("Resolving decision verification authority hostname failed: " + exception.getMessage());
                return;
            }
        }

        // Parse authenticator from command line arguments
        Optional<Authenticator<?, ?>> optionalAuthenticator = AuthenticatorFactory.createByIdentifier(commandLine.getOptionValue("crypto"));
        if (optionalAuthenticator.isEmpty()) {
            System.err.println("Parsing cryptographic algorithm failed: Unknown algorithm.");
            return;
        }
        Authenticator<?, ?> authenticator = optionalAuthenticator.get();

        if (commandLine.hasOption("f")) {
            // Start forwarding traffic between the specified interfaces w/o access control
            System.out.printf("Forward Mode: %s <-> %s\n", insecureNetworkInterface.getName(), secureNetworkInterface.getName());
            ForwardingBridge inBridge = new ForwardingBridge(insecureNetworkInterface, secureNetworkInterface);
            ForwardingBridge outBridge = new ForwardingBridge(secureNetworkInterface, insecureNetworkInterface);
            inBridge.startForwarding();
            outBridge.startForwarding();
        } else {
            // Start forwarding traffic between the specified interfaces using a secured network bridge instance
            System.out.printf("Supervisory Mode: %s <-> %s\n", insecureNetworkInterface.getName(), secureNetworkInterface.getName());
            System.out.printf("Decision Verification: incoming %s, outgoing %s\n",
                    describeVerificationAuthority(incomingVerificationAuthority),
                    describeVerificationAuthority(outgoingVerificationAuthority));
            NetworkBridge networkBridge = new NetworkBridge(insecureNetworkInterface, secureNetworkInterface,
                    authorizationAuthority, incomingVerificationAuthority, outgoingVerificationAuthority,
                    authenticationAuthority, authenticator, new ArpPredicate(),
                    new IcmpV4Predicate(), new LldpPredicate(), new PtpPredicate(), new PrpPredicate(),
                    new StpPredicate(), new SshOverTcpPredicate());
            networkBridge.open();
        }
    }

    /**
     * Resolves the address of a verifying PDP, where {@value #VERIFICATION_AUTHORITY_NONE} disables the server-aided
     * access decision verification for the direction in question.
     *
     * @param hostname the hostname or address of the verifying PDP, or {@value #VERIFICATION_AUTHORITY_NONE}
     * @return the resolved address, or {@code null} if the verification is disabled.
     * @throws UnknownHostException if the given hostname cannot be resolved
     */
    private static InetAddress resolveVerificationAuthority(String hostname) throws UnknownHostException {
        if (VERIFICATION_AUTHORITY_NONE.equalsIgnoreCase(hostname)) {
            return null;
        }
        return InetAddress.getByName(hostname);
    }

    private static String describeVerificationAuthority(InetAddress authority) {
        return authority == null ? VERIFICATION_AUTHORITY_NONE : authority.getHostAddress();
    }

    private static void displayHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("app", getCommandLineOptions(true), true);
    }

    private static void displayInterfaceList() throws PcapNativeException {
        System.out.println("Available Network Interfaces:");
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
        for (PcapNetworkInterface device : devices) {
            if (device.isUp() && !device.isLoopBack()) {
                LinkLayerAddress firstLinkLayerAddress = device.getLinkLayerAddresses().stream().findFirst().orElse(null);
                System.out.printf("    %s %s\n", device.getName(), firstLinkLayerAddress);
            }
        }
    }

    private static CommandLine parseCommandLine(String[] args, boolean parseWithRequiredOptions) throws ParseException {
        CommandLineParser parser = new DefaultParser(false);
        return parser.parse(getCommandLineOptions(parseWithRequiredOptions), args, false);
    }

    private static Options getCommandLineOptions(boolean enableRequiredOptions) {
        Options options = new Options();
        options.addOption(Option.builder("s")
                .longOpt("secure")
                .desc("set the secure interface of the program")
                .numberOfArgs(1)
                .argName("interface")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder("i")
                .longOpt("insecure")
                .desc("set the insecure interface of the program")
                .numberOfArgs(1)
                .argName("interface")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder()
                .longOpt("authorization")
                .desc("set the hostname or address of the authorization authority")
                .numberOfArgs(1)
                .argName("hostname")
                .required(enableRequiredOptions)
                .build());
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
                .longOpt("decision-verification")
                .desc("set the hostnames or addresses of the PDPs that verify the session initializations for"
                        + " incoming and for outgoing traffic; pass " + VERIFICATION_AUTHORITY_NONE + " to disable"
                        + " the verification for a direction")
                .numberOfArgs(2)
                // The argument name renders both expected values in the help dialog.
                .argName("incoming> <outgoing")
                .build());
        options.addOption(Option.builder("f")
                .longOpt("forward")
                .desc("forwards all traffic without filtering and access control")
                .build());
        options.addOption(Option.builder("l")
                .longOpt("list")
                .desc("displays network interfaces usable as secure or insecure interface of the program")
                .build());
        options.addOption(Option.builder("h")
                .longOpt("help")
                .desc("displays usage information of the program and exit")
                .build());
        return options;
    }
}
