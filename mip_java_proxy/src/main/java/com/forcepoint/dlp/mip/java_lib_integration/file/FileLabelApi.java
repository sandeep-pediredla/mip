package com.forcepoint.dlp.mip.java_lib_integration.file;

import static com.microsoft.informationprotection.MIP.loadFileProfileAsync;

import com.forcepoint.dlp.mip.java_lib_integration.*;
import com.microsoft.informationprotection.ApplicationInfo;
import com.microsoft.informationprotection.AssignmentMethod;
import com.microsoft.informationprotection.CacheStorageType;
import com.microsoft.informationprotection.ContentLabel;
import com.microsoft.informationprotection.DataState;
import com.microsoft.informationprotection.IAuthDelegate;
import com.microsoft.informationprotection.Identity;
import com.microsoft.informationprotection.IStream;
import com.microsoft.informationprotection.Label;
import com.microsoft.informationprotection.LogLevel;
import com.microsoft.informationprotection.MIP;
import com.microsoft.informationprotection.MipComponent;
import com.microsoft.informationprotection.MipContext;
import com.microsoft.informationprotection.ProtectionDescriptor;
import com.microsoft.informationprotection.ProtectionType;
import com.microsoft.informationprotection.DiagnosticConfiguration;
import com.microsoft.informationprotection.UserRights;
import com.microsoft.informationprotection.exceptions.NoPermissionsException;
import com.microsoft.informationprotection.file.FileEngineSettings;
import com.microsoft.informationprotection.file.FileProfileSettings;
import com.microsoft.informationprotection.file.IFileEngine;
import com.microsoft.informationprotection.file.IFileHandler;
import com.microsoft.informationprotection.file.IFileInspector;
import com.microsoft.informationprotection.file.IFileProfile;
import com.microsoft.informationprotection.file.IMsgAttachmentData;
import com.microsoft.informationprotection.file.IMsgInspector;
import com.microsoft.informationprotection.file.LabelingOptions;
import com.microsoft.informationprotection.file.ProtectionSettings;
import com.microsoft.informationprotection.internal.FunctionalityFilterType;
import com.microsoft.informationprotection.internal.callback.FileHandlerObserver;
import com.microsoft.informationprotection.internal.file.streams.ManagedInputStream;
import com.microsoft.informationprotection.internal.file.streams.ManagedOutputStream;
import com.microsoft.informationprotection.internal.utils.Pair;
import com.microsoft.informationprotection.policy.action.Action;
import com.microsoft.informationprotection.policy.action.MetadataAction;
import com.microsoft.informationprotection.policy.IPolicyEngine;
import com.microsoft.informationprotection.policy.IPolicyHandler;
import com.microsoft.informationprotection.policy.IPolicyProfile;
import com.microsoft.informationprotection.policy.MetadataEntry;
import com.microsoft.informationprotection.policy.PolicyEngineSettings;
import com.microsoft.informationprotection.policy.PolicyProfileSettings;
import com.microsoft.informationprotection.policy.SensitivityTypesRulePackage;
import com.microsoft.informationprotection.protection.IProtectionHandler;
import com.microsoft.informationprotection.protection.Rights;
import com.forcepoint.dlp.mip.java_lib_integration.AuditDelegate;
import com.forcepoint.dlp.mip.java_lib_integration.AuthDelegateUserCredentials;
import com.forcepoint.dlp.mip.java_lib_integration.ConsentDelegate;
import com.forcepoint.dlp.mip.java_lib_integration.ExecutionStateImpl;
import com.forcepoint.dlp.mip.java_lib_integration.FileExecutionStateImpl;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static com.forcepoint.dlp.mip.java_lib_integration.CmdOptionsStrings.USERNAME;
import static com.forcepoint.dlp.mip.java_lib_integration.CmdOptionsStrings.PASSWORD;

public class FileLabelApi {

  final static Logger logger = LogManager.getLogger(FileLabelApi.class);

  public static void main(String[] args) {

    try {
      CmdOptions cmdOptions = new CmdOptions();

      if (args == null || args.length == 0) {
        printHelp(cmdOptions);
      }

      CommandLineParser parser = new DefaultParser();
      CommandLine commandLine = parser.parse(cmdOptions.getOptions(), args);

      CacheStorageType cacheStorageType =
          commandLine.hasOption(CmdOptionsStrings.USE_STORAGE_CACHE) ? CacheStorageType.ON_DISK
              : CacheStorageType.IN_MEMORY;

      String userName = commandLine.getOptionValue(USERNAME);
      String password = commandLine.getOptionValue(PASSWORD);
      String protectionToken = commandLine.getOptionValue(CmdOptionsStrings.PROTECTIONTOKEN);
      String sccToken = commandLine.getOptionValue(CmdOptionsStrings.SCCTOKEN);
      String clientId = commandLine.getOptionValue(CmdOptionsStrings.CLIENTID);
      if (clientId == null) {
        clientId = "6b069eef-9dde-4a29-b402-8ce866edc897";
      }

      if (userName != null && password != null && protectionToken != null && sccToken != null) {
        String errorMessage =
            "Only one authentication method supported. Please pass username and password or "
                + "tokens";
        logger.info(errorMessage);
        return;
      }

      IAuthDelegate authDelegate = new AuthDelegateUserCredentials(userName, password, clientId,
          sccToken, protectionToken);

      MipComponent mipComponent =
          (commandLine.hasOption(CmdOptionsStrings.LIST) || commandLine.hasOption(CmdOptionsStrings.LIST_SENSITIVITY_TYPES))
              ? MipComponent.POLICY : MipComponent.FILE;

      logger.info("Initializing MIP");
      MIP.initialize(mipComponent,null);

      ApplicationInfo appInfo = new ApplicationInfo("00000000-0000-0000-0000-000000000001",
          "MIP SDK Java Sample", "1.0.0.0");
      String mipSamplePath = System.getProperty("user.dir") + "\\MIPSample";

      logger.info("Creating MIP context");
      boolean isAuditOverride = commandLine.hasOption(CmdOptionsStrings.ENABLE_AUDIT_DELEGATE_OVERRIDE);
      MipContext mipContext = MIP
          .createMipContext(appInfo, mipSamplePath, LogLevel.INFO, null, createDiagnosticOverride(isAuditOverride));

      List<Pair<String, String>> customSettings = new ArrayList<>();

      if (commandLine.hasOption(CmdOptionsStrings.POLICY)) {
        customSettings.add(new Pair<>("policy_file", commandLine.getOptionValue(CmdOptionsStrings.POLICY)));
        logger.info("Using policy from file: " + commandLine.getOptionValue(CmdOptionsStrings.POLICY));
      }

      if (commandLine.hasOption(CmdOptionsStrings.ENABLE_MSG)) {
        customSettings.add(new Pair<>("enable_msg_file_type", "true"));
        logger.info("Enabling msg file type operations");
      }

      String enableFunctionality = commandLine.getOptionValue(CmdOptionsStrings.ENABLEFUNCTIONALITY);
      String disableFunctionality = commandLine.getOptionValue(CmdOptionsStrings.DISABLEFUNCTIONALITY);

      if (commandLine.hasOption(CmdOptionsStrings.EXPORTPOLICY) || commandLine.hasOption(CmdOptionsStrings.EXPORTSENSITIVITYTYPES)
          || commandLine.hasOption(CmdOptionsStrings.LIST) || commandLine.hasOption(CmdOptionsStrings.LIST_SENSITIVITY_TYPES)) {
        printPolicyDetails(commandLine, cacheStorageType, userName, authDelegate, mipContext,
            customSettings, enableFunctionality, disableFunctionality);
      }

      boolean actionOnFile =
          commandLine.hasOption(CmdOptionsStrings.GET) ||
          commandLine.hasOption(CmdOptionsStrings.SET) ||
          commandLine.hasOption(CmdOptionsStrings.DELETE) ||
          commandLine.hasOption(CmdOptionsStrings.PROTECT) ||
          commandLine.hasOption(CmdOptionsStrings.UNPROTECT) ||
          commandLine.hasOption(CmdOptionsStrings.INSPECT);

      boolean getLabel = true;//commandLine.hasOption(GET);

      if (!actionOnFile && commandLine.hasOption(CmdOptionsStrings.FILE)) {
        getLabel = true;
        actionOnFile = true;
      }

      if (actionOnFile) {
        handleFileCommand(commandLine, cacheStorageType, userName, authDelegate, mipContext,
            customSettings, getLabel, enableFunctionality, disableFunctionality, commandLine.hasOption(CmdOptionsStrings.USE_STREAM_API));
      }
      logger.info("Done handling request");
    } catch (ParseException e) {
      StringWriter sw = new StringWriter();
      e.printStackTrace(new PrintWriter(sw));
      String exceptionAsString = sw.toString();

      logger.info(e.getMessage() + "\n" + exceptionAsString);
      throw new IllegalArgumentException("Failed to parse arguments");
    } catch (Exception e) {
      StringWriter sw = new StringWriter();
      e.printStackTrace(new PrintWriter(sw));
      String exceptionAsString = sw.toString();

      logger.info(e.getMessage() + "\n" + exceptionAsString);
      throw new RuntimeException(e.getMessage());
    }
  }

  private static void printHelp(CmdOptions cmdOptions) {
    HelpFormatter formatter = new HelpFormatter();

    String header = "Microsoft Information Protection File SDK Sample Version: " + getJarVersion()
        + " \nUsage:";
    StringWriter out = new StringWriter();
    PrintWriter pw = new PrintWriter(out);

    formatter.printHelp(pw, 100, header, null, cmdOptions.getOptions(), formatter.getLeftPadding(),
        formatter.getDescPadding(), null, false);
    pw.flush();

    logger.info(out.toString().substring(7));
  }

  private static String getJarVersion() {
    Package objPackage = FileLabelApi.class.getPackage();
    return objPackage.getImplementationVersion();
  }

  private static void SetPolicyLabelFilters(
    PolicyEngineSettings engineSettings,
    String enableFunctionality,
    String disableFunctionality) {
    if(enableFunctionality != null) {
      for(FunctionalityFilterType filter : CreateLabelFiltersFromString(enableFunctionality)) {
        engineSettings.configureFunctionality(filter, true);
      }
    }
    if (disableFunctionality != null) {
      for(FunctionalityFilterType filter : CreateLabelFiltersFromString(disableFunctionality)) {
        engineSettings.configureFunctionality(filter, false);
      }
    }
}

  private static void printPolicyDetails(CommandLine commandLine, CacheStorageType cacheStorageType,
      String userName, IAuthDelegate authDelegate, MipContext mipContext,
      List<Pair<String, String>> customSettings, String enableFunctionality, String disableFunctionality) throws ExecutionException, InterruptedException, IllegalArgumentException {
    PolicyProfileSettings profileSettings = new PolicyProfileSettings(mipContext, cacheStorageType);
    Future<IPolicyProfile> profile = MIP.loadPolicyProfileAsync(profileSettings);
    try {

      IPolicyProfile policyProfile = profile.get();

      PolicyEngineSettings policyEngineSettings = new PolicyEngineSettings("123", authDelegate, "",
          Locale.US.toLanguageTag());
      policyEngineSettings.setIdentity(new Identity(userName));
      policyEngineSettings.setCustomSettings(customSettings);
      policyEngineSettings.setLoadSensitivityTypes(true);

      SetPolicyLabelFilters(policyEngineSettings, enableFunctionality, disableFunctionality);

      Future<IPolicyEngine> ipolicyEngineFuture = policyProfile
          .addEngineAsync(policyEngineSettings);
      IPolicyEngine engine = ipolicyEngineFuture.get();

      if (commandLine.hasOption(CmdOptionsStrings.EXPORTPOLICY)) {
        PrintWriter writer = new PrintWriter(commandLine.getOptionValue(CmdOptionsStrings.EXPORTPOLICY),
            StandardCharsets.UTF_8.displayName());
        writer.println(engine.getPolicyDataXml());
        writer.close();
      }

      if (commandLine.hasOption(CmdOptionsStrings.EXPORTSENSITIVITYTYPES)) {
        PrintWriter writer = new PrintWriter(commandLine.getOptionValue(CmdOptionsStrings.EXPORTSENSITIVITYTYPES),
            StandardCharsets.UTF_8.displayName());
        writer.println(engine.getSensitivityTypesDataXml());
        writer.close();
      }

      if (commandLine.hasOption(CmdOptionsStrings.LIST)) {
        if (commandLine.hasOption(CmdOptionsStrings.CONTENT_FORMATS)) {
          String contentFormats = commandLine.getOptionValue(CmdOptionsStrings.CONTENT_FORMATS);
          printPolicyLabels(engine, contentFormats.split(","));
        } else {
          printPolicyLabels(engine);
        }
      }

      if (commandLine.hasOption(CmdOptionsStrings.LIST_SENSITIVITY_TYPES)) {
        printSensitivityTypes(engine);
      }

    } catch (FileNotFoundException | UnsupportedEncodingException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

private static List<FunctionalityFilterType> CreateLabelFiltersFromString(String labelFilter) throws IllegalArgumentException {
  List<FunctionalityFilterType> retVal = new ArrayList();
  String[] entries = labelFilter.split(",");
  for (String filter : entries) {
    filter = filter.trim();
    if (filter.equalsIgnoreCase("None")) {
      retVal.add(FunctionalityFilterType.NONE);
    } else if (filter.equalsIgnoreCase("CustomProtection")) {
      retVal.add(FunctionalityFilterType.CUSTOM);
    } else if (filter.equalsIgnoreCase("TemplateProtection")) {
      retVal.add(FunctionalityFilterType.TEMPLATE_PROTECTION);
    } else if (filter.equalsIgnoreCase("DoNotForwardProtection")) {
      retVal.add(FunctionalityFilterType.DoNotForwardProtection);
    } else if (filter.equalsIgnoreCase("AdhocProtection")) {
      retVal.add(FunctionalityFilterType.ADHOC_PROTECTION);
    } else if (filter.equalsIgnoreCase("HyokProtection")) {
      retVal.add(FunctionalityFilterType.HYOK_PROTECTION);
    } else if (filter.equalsIgnoreCase("PredefinedTemplateProtection")) {
      retVal.add(FunctionalityFilterType.PREDEFINED_TEMPLATE);
    } else if (filter.equalsIgnoreCase("DoubleKeyProtection")) {
      retVal.add(FunctionalityFilterType.DOUBLE_KEY_PROTECTION);
    } else if (filter.equalsIgnoreCase("DoubleKeyUserDefinedProtection")) {
      retVal.add(FunctionalityFilterType.DOUBLE_KEY_USER_DEFINED_PROTECTION);
    } else if (filter.isEmpty()) {
      //Do nothing
    } else {
      throw new IllegalArgumentException("Filter type not recognized: " + filter);
    }
  }
  return retVal;
}

private static void SetFileLabelFilters(
    FileEngineSettings engineSettings,
    String enableFunctionality,
    String disableFunctionality) {
    if(enableFunctionality != null) {
      for(FunctionalityFilterType filter : CreateLabelFiltersFromString(enableFunctionality)) {
        engineSettings.configureFunctionality(filter, true);
      }
    }
    if (disableFunctionality != null) {
      for(FunctionalityFilterType filter : CreateLabelFiltersFromString(disableFunctionality)) {
        engineSettings.configureFunctionality(filter, false);
      }
    }
}

  private static void handleFileCommand(CommandLine commandLine, CacheStorageType cacheStorageType,
                                        String userName, IAuthDelegate authDelegate, MipContext mipContext,
                                        List<Pair<String, String>> customSettings, boolean getLabel,
                                        String enableFunctionality, String disableFunctionality, boolean useStreamApi)
      throws ExecutionException, InterruptedException, IOException {
    FileEngineSettings engineSettings = new FileEngineSettings("123", authDelegate, "", "en-US");
    engineSettings.setIdentity(new Identity(userName));
    engineSettings.setCustomSettings(customSettings);
    engineSettings.setProtectionCloudEndpointBaseUrl(commandLine.getOptionValue(CmdOptionsStrings.PROTECTIONBASEURL));
    engineSettings.setPolicyCloudEndpointBaseUrl(commandLine.getOptionValue(CmdOptionsStrings.POLICYBASEURL));
    engineSettings.setEnablePFile(true);
    engineSettings.setCloud(com.microsoft.informationprotection.Cloud.COMMERCIAL);

    SetFileLabelFilters(engineSettings, enableFunctionality, disableFunctionality);

    ConsentDelegate consentDelegate = new ConsentDelegate();
    FileProfileSettings fileProfileSettings = new FileProfileSettings(mipContext, cacheStorageType, consentDelegate);

    logger.info("Loading file profile ");
    Future<IFileProfile> fileProfileFuture = loadFileProfileAsync(fileProfileSettings);
    IFileProfile fileProfile = fileProfileFuture.get();

    logger.info("Adding engine");
    Future<IFileEngine> fileEngineFuture = fileProfile.addEngineAsync(engineSettings);
    IFileEngine fileEngine = fileEngineFuture.get();

    if (!commandLine.hasOption(CmdOptionsStrings.FILE)) {
      throw new IllegalArgumentException("Missing file name");
    }

    String filePath = commandLine.getOptionValue(CmdOptionsStrings.FILE);

    logger.info("Creating file handler");

    Future<IFileHandler> fileHandlerFuture;
    DataState dataState = parseDataState(commandLine.getOptionValue(CmdOptionsStrings.DATASTATE));

    if (useStreamApi) {
      byte[] fileBuffer = FileUtils.readFileToByteArray(new File(filePath));
      fileHandlerFuture = createFileHandler(fileEngine, new ManagedInputStream(fileBuffer), filePath, new FileHandlerObserver(), dataState);
    } else {
      fileHandlerFuture = createFileHandler(fileEngine, filePath, new FileHandlerObserver(), dataState);
    }

    IFileHandler fileHandler = fileHandlerFuture.get();

    if (getLabel) {
      logger.info("Details for file: " + commandLine.getOptionValue(CmdOptionsStrings.FILE));
      ContentLabel contentLabel = fileHandler.getLabel();
      IProtectionHandler protection = fileHandler.getProtection();

      if (contentLabel == null && protection == null) {
        String errorMessage = "File is neither labeled nor protected";
        logger.info(errorMessage);
        return;
      }

      printLabel(contentLabel);
      if (protection == null) {
        logger.info("File is not protected");
      } else {
        printProtection(protection);
      }
    }

    IProtectionHandler protection = fileHandler.getProtection();
    {
      if (protection != null && !protection.getAccessCheck(Rights.Export)) {
        throw new NoPermissionsException(
            "A minimum right of EXPORT is required to change label or protection",
            protection.getProtectionDescriptor().getReferrer(), protection.getOwner());
      }
    }

    if (commandLine.hasOption(CmdOptionsStrings.SET)) {
      List<Pair<String, String>> extendedProperties = new ArrayList<>();
      if (commandLine.hasOption(CmdOptionsStrings.EXTENDEDKEY) && commandLine.hasOption(CmdOptionsStrings.EXTENDEDVALUE)) {
        extendedProperties.add(new Pair<>(commandLine.getOptionValue(CmdOptionsStrings.EXTENDEDKEY),
            commandLine.getOptionValue(CmdOptionsStrings.EXTENDEDVALUE)));
      }

      setLabel(fileHandler, fileEngine.getLabelById(commandLine.getOptionValue(CmdOptionsStrings.SET)),
          commandLine.getOptionValue(CmdOptionsStrings.JUSTIFICATION), commandLine.hasOption(CmdOptionsStrings.PRIVILEGED),
          extendedProperties, useStreamApi);

    }
    
    if (commandLine.hasOption(CmdOptionsStrings.INSPECT)) {
      inspect(fileHandler);
    }

    if (commandLine.hasOption(CmdOptionsStrings.DELETE)) {
      deleteLabel(fileHandler, commandLine.getOptionValue(CmdOptionsStrings.JUSTIFICATION), useStreamApi);
    }

    if (commandLine.hasOption(CmdOptionsStrings.PROTECT)) {
      protect(fileHandler, commandLine.getOptionValue(CmdOptionsStrings.USERS), commandLine.getOptionValue(CmdOptionsStrings.RIGHTS), useStreamApi);
    }

    if (commandLine.hasOption(CmdOptionsStrings.UNPROTECT)) {
      unprotect(fileHandler, useStreamApi);
    }
  }

  private static void printPolicyLabels(IPolicyEngine engine) {
    Collection<Label> labels = engine.getSensitivityLabels();
    printPolicyLabels(engine, labels);
  }

  private static void printPolicyLabels(IPolicyEngine engine, String[] contentFormats) {
    Collection<Label> labels = engine.getSensitivityLabels(Arrays.asList(contentFormats));

      labels.forEach(x-> System.out.println(x.getName()));

    printPolicyLabels(engine, labels);
  }

  private static void printPolicyLabels(IPolicyEngine engine, Collection<Label> labels) {
    IPolicyHandler handler = engine.createPolicyHandler(false);
    labels.stream().filter(Label::isActive).forEach(label -> {
      ExecutionStateImpl executionState = new ExecutionStateImpl(label);
      Collection<Action> actions = handler.computeActions(executionState);
      printPolicyLabel(label, actions);
    });
  }

  private static void printPolicyLabel(Label label, Collection<Action> actions) {
    logger.info("Label Name: " + label.getName() + ", Label ID: " + label.getId());
    List<String> contentFormats = label.getContentFormats();
    if (!contentFormats.isEmpty()) {
        logger.info("\tContent Formats: " + contentFormats.toString());
    }

    if (actions == null) {
      return;
    }

    for (Action action : actions) {
      System.out
          .println("\tAction Type: " + action.getActionType() + ", Action Id: " + action.getId());

      if(action instanceof MetadataAction) {
        MetadataAction metadataAction = (MetadataAction) action;
        logger.info("\t\tMetadata to add:");
        for (MetadataEntry metadata : metadataAction.getMetadataToAdd()) {
          logger.info("\t\t" + metadata.getKey() + ": " + metadata.getValue());
        }
      }
    }

  }

  private static void printSensitivityTypes(IPolicyEngine engine) {
    for (SensitivityTypesRulePackage sensitivityType : engine.getSensitivityTypes()) {
      logger.info("RulePackageId: " + sensitivityType.getRulePackageId());
      logger.info("RulePackage: " + sensitivityType.getRulePackage());
    }
  }

  private static DiagnosticConfiguration createDiagnosticOverride(boolean isAuditOverride) {
    DiagnosticConfiguration diagnosticConfiguration = new DiagnosticConfiguration();
    if(isAuditOverride) {
      diagnosticConfiguration.setAuditDelegate(new AuditDelegate());
    }
    diagnosticConfiguration.setLocalCachingEnabled(true);
    return diagnosticConfiguration;
  }

  private static Future<IFileHandler> createFileHandler(IFileEngine engine, String filePath,
      FileHandlerObserver observer, DataState dataState) {
    return engine.createFileHandlerAsync(filePath, filePath, false /*Disable audit discovery*/,
        observer, new FileExecutionStateImpl(dataState));
  }

  private static Future<IFileHandler> createFileHandler(IFileEngine engine, IStream inputStream, String filePath,
                                                        FileHandlerObserver observer, DataState dataState) {
    return engine.createFileHandlerAsync(inputStream, filePath, false /*Disable audit discovery*/,
            observer, new FileExecutionStateImpl(dataState));
  }

  private static DataState parseDataState(String dataState) {
    if (dataState == null || dataState.length() == 0 || dataState.equalsIgnoreCase("Rest")) {
      return DataState.REST;
    }
    if (dataState.equalsIgnoreCase("Use")) {
      return DataState.USE;
    }
    if (dataState.equalsIgnoreCase("Motion")) {
      return DataState.MOTION;
    }

    throw new IllegalArgumentException("Content state is invalid");
  }

  private static void printLabel(ContentLabel contentLabel) {
    if (contentLabel == null) {
      logger.info("File is not labeled");
      return;
    }
    printContentLabel(contentLabel);
  }

  private static void printContentLabel(ContentLabel contentLabel) {
    Label label = contentLabel.label;
    logger.info("File is labeled as: " + label.getName());
    logger.info("Id: " + label.getId());
    String isPrivileged =
        contentLabel.assignmentMethod == AssignmentMethod.PRIVILEGED ? "True" : "False";
    logger.info("Privileged: " + isPrivileged);
    logger.info("Label Creation time: " + contentLabel.creationTime);
  }

  private static void printProtection(IProtectionHandler protection) {
    ProtectionDescriptor protectionDescriptor = protection.getProtectionDescriptor();
    if (protectionDescriptor.getProtectionType() == ProtectionType.TEMPLATE_BASED) {
      logger.info("File is protected with template");
    } else {
      logger.info("File is protected with custom permissions");
    }
    logger.info("Name: " + protectionDescriptor.getName());
    logger.info("Description: " + protectionDescriptor.getDescription());
    logger.info("Protection Type: " + protectionDescriptor.getProtectionType());
    logger.info("Template Id: " + protectionDescriptor.getTemplateId());
    if (protectionDescriptor.getProtectionType() == ProtectionType.CUSTOM) {
      protectionDescriptor.getUserRights().forEach(item -> {
        logger.info("Users:");
        item.getUsers().forEach(user -> System.out.print(" " + user));
        System.out.print("Rights:");
        item.getRights().forEach(right -> System.out.print(" " + right));
      });
    } else {
      logger.info("Template Id: " + protectionDescriptor.getTemplateId());
    }
  }

  private static boolean setLabel(IFileHandler fileHandler, Label label,
                                  String justification, Boolean privileged, List<Pair<String, String>> extendedProperties, boolean useStreamApi)
      throws ExecutionException, InterruptedException, IOException {

    if (label == null) {
      throw new IllegalArgumentException("Label is missing");
    }

    // The original input (file/stream) is not modified. Only when calling CommitAsync will the
    // changes be written to the output (stream/file)
    LabelingOptions labelingOptions = new LabelingOptions();
    labelingOptions.setJustificationMessage(justification);
    labelingOptions.extendedProperties = extendedProperties;

    labelingOptions.setAssignmentMethod(AssignmentMethod.AUTO);
    if (privileged) {
      labelingOptions.setAssignmentMethod(AssignmentMethod.PRIVILEGED);
    }

    logger.info("Setting label");
    fileHandler.setLabel(label, labelingOptions, new ProtectionSettings());

    boolean committed = commitAsync(fileHandler, useStreamApi);
    logger.info(committed ? "Label was added to file" : "File was already labeled");

    return committed;
  }

  private static boolean commitAsync(IFileHandler fileHandler, boolean useStreamApi)
          throws ExecutionException, InterruptedException, IOException {

    String outputFile = fileHandler.getOutputFileName();
    String modifiedFile =
        FilenameUtils.getFullPath(outputFile) + FilenameUtils.getBaseName(outputFile) + "_modified."
            + FilenameUtils.getExtension(outputFile);

    if (FilenameUtils.getExtension(outputFile).equalsIgnoreCase("pfile")) {
      String oldFullName = FilenameUtils.getBaseName(outputFile);
      String oldExtension = FilenameUtils.getExtension(oldFullName);
      String oldName = FilenameUtils.getBaseName(oldFullName);
      modifiedFile =
          FilenameUtils.getFullPath(outputFile) + oldName + "_modified." + oldExtension + ".pfile";
    }
    logger.info("Committing changes");

    boolean result;
    if (useStreamApi) {
      ManagedOutputStream outputStream = new ManagedOutputStream();
      result = fileHandler.commitAsync(outputStream).get();
      if (result) {
        FileUtils.writeByteArrayToFile(new File(modifiedFile), outputStream.toByteArray());
      }
    } else {
      result = fileHandler.commitAsync(modifiedFile).get();
    }

    if (result) {
      logger.info("New file created: " + modifiedFile);
    }
    return result;
  }

  private static Boolean deleteLabel(IFileHandler fileHandler, String justification, boolean useStreamApi)
      throws ExecutionException, InterruptedException, IOException {
    if (justification == null || justification.isEmpty()) {
      throw new IllegalArgumentException("Justification is missing");
    }

    // The original input (file/stream) is not modified. Only when calling CommitAsync will the
    // changes be written to the output (stream/file)
    LabelingOptions labelingOptions = new LabelingOptions();
    labelingOptions.setJustificationMessage(justification);
    fileHandler.deleteLabel(labelingOptions);

    boolean committed = commitAsync(fileHandler, useStreamApi);
    logger.info(committed ? "Label was removed from file" : "Failed to remove label");

    return committed;
  }

  private static boolean protect(IFileHandler fileHandler, String users, String rights, boolean useStreamApi)
      throws ExecutionException, InterruptedException, IOException {
    if (users == null || rights == null) {
      throw new IllegalArgumentException("Users or rights are missing");
    }

    // The original input (file/stream) is not modified. Only when calling CommitAsync will the
    // changes be written to the output (stream/file)
    List<UserRights> userRights = new ArrayList<>();
    userRights
        .add(new UserRights(Arrays.asList(users.split(",")), Arrays.asList(rights.split(","))));

    Calendar cal = Calendar.getInstance();
    cal.setTime(new Date());
    cal.add(Calendar.MONTH, 1);
    cal.getTime();

    ProtectionDescriptor protectionDescriptor = new ProtectionDescriptor(userRights, null);
    protectionDescriptor.setContentValidUntil(cal.getTime());
    fileHandler.setProtection(protectionDescriptor, new ProtectionSettings());

    boolean committed = commitAsync(fileHandler, useStreamApi);
    logger.info(committed ? "protection was added to file" : "Failed to apply protection");
    return committed;
  }

  private static boolean unprotect(IFileHandler fileHandler, boolean useStreamApi)
          throws ExecutionException, InterruptedException, IOException {
    // The original input (file/stream) is not modified. Only when calling CommitAsync will the
    // changes be written to the output (stream/file)
    fileHandler.removeProtection();

    boolean committed = commitAsync(fileHandler, useStreamApi);
    System.out
        .println(committed ? "protection was removed from file" : "Failed to remove protection");
    return committed;
  }

  private static boolean inspect(IFileHandler fileHandler)
      throws ExecutionException, InterruptedException {
    Future<IFileInspector> resultFuture = fileHandler.inspectAsync();
    IFileInspector inspector = resultFuture.get();
    if (inspector != null) {
      logger.info("New inspector created: ");
      switch (inspector.getType()) {
        case Msg:
          if (inspector instanceof IMsgInspector) {
            IMsgInspector msgInspector = (IMsgInspector)inspector;
            logger.info("Message body size:" + msgInspector.getBody().length);
            logger.info("Message body body code page :" + msgInspector.getCodePage());
            logger.info("Message attachments count :" + msgInspector.getAttachments().size());
            for (IMsgAttachmentData attachment : msgInspector.getAttachments()) {
              logger.info("Attachment Name:" + attachment.getName());
              logger.info("Attachment Long Name:" + attachment.getLongName());
              logger.info("Attachment Path:" + attachment.getPath());
              logger.info("Attachment Long Path:" + attachment.getLongPath());
              logger.info("Attachment Size:" + attachment.getBytes().length);
            }
          } else {
            throw new IllegalArgumentException("unable to create inspector to this file.");
          }
          break;
        case Unknown:
          logger.error("Not supported file format, use unprotect and 3rd party applications for it.");
          throw new IllegalArgumentException("unable to create inspector to this file.");
        default:
          throw new IllegalArgumentException("unable to create inspector to this file.");
      }
    } else {
      throw new IllegalArgumentException("unable to create inspector to this file.");
    }
    return true;
  }
}
