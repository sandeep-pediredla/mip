package com.forcepoint.dlp.mip.java_lib_integration.file;

import com.forcepoint.dlp.mip.java_lib_integration.CmdOptionsStrings;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

public class CmdOptions {

  private Options options = new Options();

  public CmdOptions() {
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.POLICY).hasArgs().type(String.class)
        .desc("Sets policy path to local policy file").build());
    options.addOption(Option.builder("l").longOpt(CmdOptionsStrings.LIST).type(boolean.class)
        .desc("Gets all available labels with their ID values").build());
    options.addOption(Option.builder("g").longOpt(CmdOptionsStrings.GET).type(boolean.class)
        .desc("Gets the labels and protection of the given file").build());
    options.addOption(
        Option.builder("f").longOpt(CmdOptionsStrings.FILE).hasArgs().type(String.class).desc("File path").build());
    options.addOption(
        Option.builder("s").longOpt(CmdOptionsStrings.SET).hasArgs().type(String.class).desc("Sets label by id")
            .build());
    options.addOption(Option.builder("d").longOpt(CmdOptionsStrings.DELETE).type(boolean.class)
        .desc("Delete existing label from the given file").build());
    options.addOption(Option.builder("c").longOpt(CmdOptionsStrings.DATASTATE).hasArgs().type(String.class)
        .desc("State of the content, REST by default").build());
    options.addOption(Option.builder("j").longOpt(CmdOptionsStrings.JUSTIFICATION).hasArgs().type(String.class)
        .desc("Justification message to applied on set or remove label").build());
    options.addOption(Option.builder("p").longOpt(CmdOptionsStrings.PROTECT).type(boolean.class).desc(
        "Protects the given file with custom permissions, according to given lists of users and "
            + "rights")
        .build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.USERS).hasArgs().type(String.class)
        .desc("Comma-separated list of users").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.RIGHTS).hasArgs().type(String.class)
        .desc("Comma-separated list of rights").build());
    options.addOption(Option.builder("u").longOpt(CmdOptionsStrings.UNPROTECT).type(boolean.class)
        .desc("Removes protection from the given file").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.EXPORTPOLICY).hasArgs().type(String.class)
        .desc("Set path to export downloaded policy to").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.EXPORTSENSITIVITYTYPES).hasArgs().type(String.class)
        .desc("Set path to export downloaded sensitivity types to").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.EXTENDEDKEY).hasArgs().type(String.class)
        .desc("Set an extended property key").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.EXTENDEDVALUE).hasArgs().type(String.class)
        .desc("Set the extended property value").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.USERNAME).hasArgs().type(String.class)
        .desc("Sets username for authentication").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PASSWORD).hasArgs().type(String.class)
        .desc("Sets password for authentication").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.CLIENTID).hasArgs().type(String.class)
        .desc("Sets ClientID for authentication").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.SCCTOKEN).hasArgs().type(String.class)
        .desc("SccToken authentication").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PROTECTIONTOKEN).hasArgs().type(String.class)
        .desc("ProtectionToken authentication").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PROTECTIONBASEURL).hasArgs().type(String.class)
        .desc("Cloud endpoint base url for protection operations (e.g. api.aadrm.com)").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.POLICYBASEURL).hasArgs().type(String.class)
        .desc("Cloud endpoint base url for policy operations (e.g. dataservice.protection.outlook.com)").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PRIVILEGED).type(boolean.class)
        .desc("The label will be privileged label and will override any label").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.USE_STORAGE_CACHE).type(boolean.class)
        .desc("(Optional) Profile uses a to cache engines.").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.LIST_SENSITIVITY_TYPES).type(boolean.class)
        .desc("Gets all available custom sensitivity types for the tenant").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.INSPECT).type(boolean.class)
        .desc("(Optional) Inspect file, doesn't unprotect / protect just views information about the file.").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.ENABLE_MSG).type(boolean.class)
        .desc("Enable msg file operations, labelling is not supported for msg files").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.ENABLEFUNCTIONALITY).hasArgs().type(String.class)
        .desc("List of functionality to enable").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.DISABLEFUNCTIONALITY).hasArgs().type(String.class)
        .desc("List of functionality to disable").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.ENABLE_AUDIT_DELEGATE_OVERRIDE).hasArgs().type(boolean.class)
        .desc("Enable audit delegate override").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.USE_STREAM_API).type(boolean.class)
        .desc("Use stream based APIs for input/output.").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.CONTENT_FORMAT).hasArgs().type(String.class)
        .desc("Content format like email etc.").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.CONTENT_FORMATS).hasArgs().type(String.class)
        .desc("The list of content formats like email,file etc.").build());
  }

  public Options getOptions() {
    return options;
  }
}
