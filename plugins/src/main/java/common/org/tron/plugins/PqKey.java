package org.tron.plugins;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name = "pq-key",
    mixinStandardHelpOptions = true,
    version = "pq-key command 1.0",
    description = "Manage post-quantum key files.",
    subcommands = {CommandLine.HelpCommand.class,
        PqKeyNew.class
    },
    commandListHeading = "%nCommands:%n%nThe most commonly used pq-key commands are:%n"
)
public class PqKey {
}
