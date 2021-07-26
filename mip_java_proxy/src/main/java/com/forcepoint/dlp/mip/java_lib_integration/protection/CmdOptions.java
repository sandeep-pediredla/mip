package com.forcepoint.dlp.mip.java_lib_integration.protection;

import com.forcepoint.dlp.mip.java_lib_integration.CmdOptionsStrings;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

public class CmdOptions {

  private Options options = new Options();

  public CmdOptions() {
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.USERNAME).hasArgs().type(String.class)
        .desc("Sets username for authentication").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PASSWORD).hasArgs().type(String.class)
        .desc("Sets password for authentication").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.CLIENTID).hasArgs().type(String.class)
        .desc("Sets ClientID for authentication").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.TOKEN).hasArgs().type(String.class)
        .desc("ProtectionToken authentication").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.BASEURL).hasArgs().type(String.class)
        .desc("Cloud endpoint base url (e.g. api.aadrm.com)").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.LOCALE).hasArgs().type(String.class)
        .desc("Set locale/language (default 'en-US')").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.ENGINE_ID).hasArgs().type(String.class)
        .desc("Load an engine from profile's storage cache by id rather than creating a new one")
        .build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.STATUS).type(boolean.class)
        .desc("Show protection status (i.e. template, rights, etc.) of <file>.").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PROTECT_AD_HOC).type(boolean.class)
        .desc("Protect <file> by assigning <users> specific <rights>.").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PROTECT_TEMPLATE).type(boolean.class)
        .desc("Protect <file> with <templateId>.").build());
    options.addOption(Option.builder("u").longOpt(CmdOptionsStrings.UNPROTECT).type(boolean.class)
        .desc("Removes protection from the given file").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.LIST_TEMPLATES).type(boolean.class)
        .desc("Lists all templates available to <user>.").build());
    options.addOption(
        Option.builder("f").longOpt(CmdOptionsStrings.FILE).hasArgs().type(String.class).desc("File path").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.USERS).hasArgs().type(String.class)
        .desc("Comma-separated list of users").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.RIGHTS).hasArgs().type(String.class)
        .desc("Comma-separated list of rights").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.ROLES).hasArgs().type(String.class)
        .desc("Comma-separated list of roles").build());
    options.addOption(
        Option.builder().longOpt(CmdOptionsStrings.TEMPLATE_ID).hasArgs().type(String.class).desc("Template ID")
            .build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.USE_ASYNC_API).type(boolean.class)
        .desc("Uses async APIs (as opposed to synchronous APIs)").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.DOUBLE_KEY_URL).hasArgs().type(String.class)
        .desc("Double key url to use for custom protection").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PRELICENSE_FILE).hasArgs().type(String.class)
        .desc("Output file for the prelicense").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PRELICENSE_FORMAT).hasArgs().type(String.class)
        .desc("Format to save the prelicense, 'Json' or 'Xml'").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.PARSE_PUBLISHING_LICENSE).type(boolean.class)
        .desc("Parse a publishing license and show the details.").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.REPUBLISHINGLICENSE_FILE).hasArgs().type(String.class)
        .desc("Input file for the republishing license").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.DELEGATED_USER).hasArgs().type(String.class)
        .desc("operation performed on behalf of <delegatedUser>. App-based <token> is required for delegation scenarios.").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.DELEGATION_END_USER_LICENSE).type(boolean.class)
        .desc("Create delegate end user licenses.  Use the 'users' option to specify users and the 'file' option to specify the publishing license").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.DELEGATION_LICENSE).type(boolean.class)
        .desc("Create delegate licenses.  Use the 'users' option to specify users and the 'file' option to specify the publishing license").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.OUT_FILE).hasArgs().type(String.class)
        .desc("Override the default output file name for the chosen operation").build());
    options.addOption(Option.builder().longOpt(CmdOptionsStrings.URI_REDIRECTIONS).hasArgs().type(String.class)
        .desc("Sets a list of redirections in the format of originalUri1,redirectUri1;originalUri2,redirectUri2").build());
  }

  public Options getOptions() {
    return options;
  }
}
