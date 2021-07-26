package com.forcepoint.dlp.mip.java_lib_integration.protection;

import com.forcepoint.dlp.mip.java_lib_integration.AuthDelegateUserCredentials;
import com.forcepoint.dlp.mip.java_lib_integration.CmdOptionsStrings;
import com.forcepoint.dlp.mip.java_lib_integration.ConsentDelegate;
import com.microsoft.informationprotection.ApplicationInfo;
import com.microsoft.informationprotection.CacheStorageType;
import com.microsoft.informationprotection.IAuthDelegate;
import com.microsoft.informationprotection.Identity;
import com.microsoft.informationprotection.LogLevel;
import com.microsoft.informationprotection.MIP;
import com.microsoft.informationprotection.MipComponent;
import com.microsoft.informationprotection.MipContext;
import com.microsoft.informationprotection.PreLicenseFormat;
import com.microsoft.informationprotection.ProtectionDescriptor;
import com.microsoft.informationprotection.UserRights;
import com.microsoft.informationprotection.UserRoles;
import com.microsoft.informationprotection.internal.protection.ConsumptionSettings;
import com.microsoft.informationprotection.internal.protection.LicenseApplicationData;
import com.microsoft.informationprotection.internal.protection.LicenseNameAndDescriptionItem;
import com.microsoft.informationprotection.internal.protection.DelegationLicenseSettings;
import com.microsoft.informationprotection.internal.protection.GetTemplatesSettings;
import com.microsoft.informationprotection.internal.protection.ProtectionEngineSettings;
import com.microsoft.informationprotection.internal.protection.ProtectionProfileSettings;
import com.microsoft.informationprotection.internal.protection.PublishingLicenseInfo;
import com.microsoft.informationprotection.internal.protection.PublishingSettings;
import com.microsoft.informationprotection.internal.protection.TemplateDescriptor;
import com.microsoft.informationprotection.protection.IDelegationLicense;
import com.microsoft.informationprotection.protection.IProtectionEngine;
import com.microsoft.informationprotection.protection.IProtectionHandler;
import com.microsoft.informationprotection.protection.IProtectionProfile;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;
import java.util.TimeZone;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.io.FileUtils;

public class ProtectionApi {

  public static void main(String[] args) throws IOException {
    DataInputStream dataInputStream = null;
    DataOutputStream dataOutputStream = null;
    FileInputStream inputStream = null;
    FileOutputStream outputStream = null;

    try {
      CmdOptions cmdOptions = new CmdOptions();
      CommandLineParser parser = new DefaultParser();
      CommandLine commandLine = parser.parse(cmdOptions.getOptions(), args);

      String userName = commandLine.getOptionValue(CmdOptionsStrings.USERNAME);
      String password = commandLine.getOptionValue(CmdOptionsStrings.PASSWORD);
      String token = commandLine.getOptionValue(CmdOptionsStrings.TOKEN);
      String clientId = commandLine.getOptionValue(CmdOptionsStrings.CLIENTID);
      if (clientId == null) {
        clientId = "6b069eef-9dde-4a29-b402-8ce866edc897";
      }

      if (userName != null && password != null && token != null) {
        String errorMessage =
            "Only one authentication method supported. Please pass username and password "
                + "or token";
        System.out.println(errorMessage);
        throw new RuntimeException(errorMessage);
      }

      IAuthDelegate authDelegate = new AuthDelegateUserCredentials(userName, password, clientId, "",
          token);

      MIP.initialize(MipComponent.PROTECTION, null);

      ApplicationInfo appInfo = new ApplicationInfo("00000000-0000-0000-0000-000000000001",
          "MIP SDK Java Sample", "1.0.0.0");

      String mipSamplePath = System.getProperty("user.dir") + "\\MIPSample";
      MipContext mipContext = MIP
          .createMipContext(appInfo, mipSamplePath, LogLevel.TRACE, null, null);

      String filePath = commandLine.getOptionValue(CmdOptionsStrings.FILE);
      if(commandLine.hasOption(CmdOptionsStrings.PARSE_PUBLISHING_LICENSE)) {
        if (filePath == null) {
          throw new Exception("Unable to parse a publishing license without a file");
        }
        ParsePublishingLicense(filePath);
        return;
      }

      String outFile = null;
      if(commandLine.hasOption(CmdOptionsStrings.OUT_FILE)) {
        outFile = commandLine.getOptionValue(CmdOptionsStrings.OUT_FILE);
      }
      
      ProtectionProfileSettings profileSetting = new ProtectionProfileSettings(mipContext,
          CacheStorageType.IN_MEMORY, new ConsentDelegate());
      ProtectionEngineSettings engineSetting = getProtectionEngineSettings(commandLine,
          authDelegate);

      if(commandLine.hasOption(CmdOptionsStrings.URI_REDIRECTIONS)) {
        setRedirections(commandLine.getOptionValue(CmdOptionsStrings.URI_REDIRECTIONS), profileSetting);
      }

      boolean useAsyncApi = commandLine.hasOption(CmdOptionsStrings.USE_ASYNC_API);
      IProtectionEngine engine = getProtectionEngine(useAsyncApi, profileSetting, engineSetting);

      System.out.println("Protection engine ID: " + engine.getSettings().getEngineId());

      String delegatedUser = "";
      if (commandLine.hasOption(CmdOptionsStrings.DELEGATED_USER)) {
        delegatedUser = commandLine.getOptionValue(CmdOptionsStrings.DELEGATED_USER);
      }

      if (commandLine.hasOption(CmdOptionsStrings.LIST_TEMPLATES)) {
        printListOfTemplates(useAsyncApi, engine, delegatedUser);
        return;
      }

      validateFilePath(filePath);

      String prelicenseFile = null;
      if (commandLine.hasOption(CmdOptionsStrings.PRELICENSE_FILE)) {
        prelicenseFile = commandLine.getOptionValue(CmdOptionsStrings.PRELICENSE_FILE);
      }

      String republishingLicenseFile = null;
      if (commandLine.hasOption(CmdOptionsStrings.REPUBLISHINGLICENSE_FILE)) {
        republishingLicenseFile = commandLine.getOptionValue(CmdOptionsStrings.REPUBLISHINGLICENSE_FILE);
      }

      /* The Protected format used is <LicenseSize - sizeof(int)><License><DataSize - sizeof(int)
      ><EncryptedData> */
      if (commandLine.hasOption(CmdOptionsStrings.PROTECT_TEMPLATE) || commandLine.hasOption(CmdOptionsStrings.PROTECT_AD_HOC)) {
        ProtectionDescriptor descriptor = getProtectionDescriptorFromInput(commandLine);
        PublishingSettings publishingSettings = new PublishingSettings(descriptor);

        if (prelicenseFile != null) {
          publishingSettings.setPreLicenseUserEmail(userName);
        }

        if (republishingLicenseFile != null) {
          File republishFile = FileCheck(republishingLicenseFile, "Republishing license");

          publishingSettings.setPublishingLicenseForRepublish(FileUtils.readFileToByteArray(republishFile));
        }

        IProtectionHandler handler = getProtectionHandlerFromPublishingSettings(useAsyncApi, engine,
            publishingSettings);

        byte[] license = handler.getSerializedPublishingLicense();

        SaveToFile(filePath + "_license", license);

        String outputFileName = outFile == null ? filePath + "_protected" : outFile;
        outputStream = new FileOutputStream(new File(outputFileName));
        dataOutputStream = new DataOutputStream(outputStream);

        dataOutputStream.writeInt(license.length);
        dataOutputStream.write(license);

        File inFile = new File(filePath);
        byte[] data = FileUtils.readFileToByteArray(inFile);
        int encryptedDataLength = (int) handler.getProtectedContentLength(data.length, true);
        byte[] encryptedData = new byte[encryptedDataLength];
        handler.encryptBuffer(0, data, encryptedData, true);

        dataOutputStream.writeInt(data.length);
        dataOutputStream.write(encryptedData);

        if (prelicenseFile != null) {
          byte[] preLicense = handler.getSerializedPreLicense(GetPreLicenseFormat(commandLine));
          FileUtils.writeByteArrayToFile(new File(prelicenseFile), preLicense);
        }
      } else if (commandLine.hasOption(CmdOptionsStrings.UNPROTECT)) {
        File file = new File(filePath);
        inputStream = new FileInputStream(file);
        dataInputStream = new DataInputStream(inputStream);

        byte[] license = readLicense(dataInputStream);
        IProtectionHandler handler;

        if (prelicenseFile != null) {
          if (IsFileXrml(prelicenseFile)) {
            throw new RuntimeException("Mip cannot currently process xml prelicenses");
          }

          File prelicenseFileToRead = FileCheck(prelicenseFile, "Prelicense");

          byte[] preLicense = FileUtils.readFileToByteArray(prelicenseFileToRead);
          handler = getProtectionHandlerFromLicense(useAsyncApi, engine, license, preLicense);
        } else {
          handler = getProtectionHandlerFromLicense(useAsyncApi, engine, license);
        }

        int decryptDataLength = dataInputStream.readInt();
        int encryptedDataLength =
            (int) file.length() - (license.length + 8); // license + LicenseSize + dataSize
        byte[] encryptedData = new byte[encryptedDataLength];
        dataInputStream.read(encryptedData);
        byte[] clearData = new byte[decryptDataLength];

        handler.decryptBuffer(0, encryptedData, clearData, true);
        String outputFileName = outFile == null ? filePath + "_unprotected" : outFile;
        FileUtils.writeByteArrayToFile(new File(outputFileName), clearData, 0, decryptDataLength);
      } else if (commandLine.hasOption(CmdOptionsStrings.STATUS)) {
        File file = new File(filePath);
        inputStream = new FileInputStream(file);
        dataInputStream = new DataInputStream(inputStream);

        byte[] license = readLicense(dataInputStream);
        IProtectionHandler handler = getProtectionHandlerFromLicense(useAsyncApi, engine, license);
        ProtectionDescriptor descriptor = handler.getProtectionDescriptor();
        printStatusFromDescriptor(descriptor);
      } else if (commandLine.hasOption(CmdOptionsStrings.REGISTER_REVOKE)) {
        File file = new File(filePath);
        inputStream = new FileInputStream(file);
        dataInputStream = new DataInputStream(inputStream);
        byte[] license = readLicense(dataInputStream);
        registerContent(useAsyncApi, engine, license, file.getName());
        revokeContent(useAsyncApi, engine, license);
      } else if (commandLine.hasOption(CmdOptionsStrings.DELEGATION_END_USER_LICENSE) || commandLine.hasOption(CmdOptionsStrings.DELEGATION_LICENSE)) {
        createDelegationLicense(useAsyncApi, engine, filePath, commandLine);
      }
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Failed to parse arguments");
    } catch (Exception e) {
      System.out.println(e.getMessage());
      e.printStackTrace();
      throw new RuntimeException(e.getMessage());
    } finally {
      if (dataInputStream != null) {
        dataInputStream.close();
      }
      if (dataOutputStream != null) {
        dataOutputStream.close();
      }
      if (outputStream != null) {
        outputStream.close();
      }
      if (inputStream != null) {
        inputStream.close();
      }
    }
  }

  private static IProtectionHandler getProtectionHandlerFromPublishingSettings(boolean useAsyncApi,
      IProtectionEngine engine, PublishingSettings publishingSettings)
      throws ExecutionException, InterruptedException {
    IProtectionHandler handler;

    if (useAsyncApi) {
      handler = engine.createProtectionHandlerForPublishingAsync(publishingSettings).get();
    } else {
      handler = engine.createProtectionHandlerForPublishing(publishingSettings);
    }

    return handler;
  }

  private static void printStatusFromDescriptor(ProtectionDescriptor descriptor) {
    System.out.println("PROTECTION STATUS");
    System.out.println("\tType: " + descriptor.getProtectionType().toString());
    System.out.println("\tTemplateId: " + descriptor.getTemplateId());
    System.out.println("\tLabelId: " + descriptor.getLabelId());
    System.out.println("\tContentId: " + descriptor.getContentId());
    System.out.println("\tName: " + descriptor.getName());
    System.out.println("\tDescription: " + descriptor.getDescription());
    System.out.println("\tOwner: " + descriptor.getOwner());
    System.out.println("\tReferrer: " + descriptor.getReferrer());
    Date d = descriptor.getContentValidUntil();
    String hasValue = d != null ? "true" : "false";
    System.out.println("\tDoes content expire: " + hasValue);
    if (d != null) {
      System.out.println("\tContent valid until: " + d.toString());
    }
    System.out.println("\tAllows offline access: " + descriptor.isAllowOfflineAccess());
  }

  private static ProtectionDescriptor getProtectionDescriptorFromInput(CommandLine commandLine)
      throws Exception {
    if (commandLine.hasOption(CmdOptionsStrings.PROTECT_TEMPLATE)) {
      String templateId = commandLine.getOptionValue(CmdOptionsStrings.TEMPLATE_ID);
      if (templateId == null) {
        throw new Exception(
            "You cannot specify template protection without specifying templateId.");
      }

      return new ProtectionDescriptor(templateId);
    }

    if (commandLine.getOptionValue(CmdOptionsStrings.USERS) == null) {
      throw new Exception("You cannot specify Ad-Hoc protection without specifying users.");
    }

    if (commandLine.getOptionValue(CmdOptionsStrings.RIGHTS) == null && commandLine.getOptionValue(CmdOptionsStrings.ROLES) == null) {
      throw new Exception(
          "You cannot specify Ad-Hoc protection without specifying rights or roles.");
    }

    String doubleKeyUrl = "";
    if (commandLine.hasOption(CmdOptionsStrings.DOUBLE_KEY_URL)) {
      doubleKeyUrl = commandLine.getOptionValue(CmdOptionsStrings.DOUBLE_KEY_URL);
    }

    String[] users = commandLine.getOptionValue(CmdOptionsStrings.USERS).split(",");
    ProtectionDescriptor adHocDescriptor;

    if (commandLine.getOptionValue(CmdOptionsStrings.RIGHTS) != null) {
      String[] rights = commandLine.getOptionValue(CmdOptionsStrings.RIGHTS).split(",");
      ArrayList<UserRights> list = new ArrayList<>();
      list.add(new UserRights(Arrays.asList(users), Arrays.asList(rights)));
      adHocDescriptor = new ProtectionDescriptor(list, null);
    } else {
      String[] roles = commandLine.getOptionValue(CmdOptionsStrings.ROLES).split(",");
      ArrayList<UserRoles> list = new ArrayList<>();
      list.add(new UserRoles(Arrays.asList(users), Arrays.asList(roles)));
      adHocDescriptor = new ProtectionDescriptor(null, list);
    }

    adHocDescriptor.setDoubleKeyUrl(doubleKeyUrl);

    return adHocDescriptor;
  }

  private static void validateFilePath(String path) throws Exception {
    if (path == null) {
      throw new Exception("Missing File!");
    }
  }

  private static void printListOfTemplates(boolean useAsyncApi, IProtectionEngine engine, String delegatedUser)
      throws ExecutionException, InterruptedException {
    List<TemplateDescriptor> templates;
    GetTemplatesSettings settings = new GetTemplatesSettings();
    settings.setDelegatedUserEmail(delegatedUser);

    if (useAsyncApi) {
      templates = engine.getTemplatesAsync(settings).get();
    } else {
      templates = engine.getTemplates(settings);
    }

    System.out.println("TEMPLATES");
    templates.forEach(temp -> System.out.println("\t" + temp.getId()));
  }

  private static ProtectionEngineSettings getProtectionEngineSettings(CommandLine commandLine,
      IAuthDelegate authDelegate) {
    String engineId = commandLine.hasOption(CmdOptionsStrings.ENGINE_ID) ? UUID.randomUUID().toString() : null;
    String locale = commandLine.hasOption(CmdOptionsStrings.LOCALE) ? "en-us" : null;
    String endpointUrl = commandLine.hasOption(CmdOptionsStrings.BASEURL) ? "api.aadrm.com" : null;

    ProtectionEngineSettings engineSetting = new ProtectionEngineSettings(engineId, authDelegate,
        "clientData",
        locale);

    if (endpointUrl != null && !endpointUrl.startsWith("http")) {
      endpointUrl = "https://" + endpointUrl;
    }

    engineSetting.setCloudEndpointBaseUrl(endpointUrl);

    engineSetting.setIdentity(new Identity(commandLine.getOptionValue(CmdOptionsStrings.USERNAME)));
    return engineSetting;
  }

  private static IProtectionEngine getProtectionEngine(boolean useAsyncApi,
      ProtectionProfileSettings profileSettings, ProtectionEngineSettings engineSetting)
      throws ExecutionException, InterruptedException {
    IProtectionProfile profile;

    if (useAsyncApi) {
      profile = MIP.loadProtectionProfileAsync(profileSettings).get();
    } else {
      profile = MIP.loadProtectionProfile(profileSettings);
    }

    return profile.addEngine(engineSetting);
  }

  private static byte[] readLicense(DataInputStream stream) throws IOException {
    int licenseLength = stream.readInt();
    byte[] licenseBytes = new byte[licenseLength];
    stream.read(licenseBytes, 0, licenseLength);
    return licenseBytes;
  }

  private static IProtectionHandler getProtectionHandlerFromLicense(boolean useAsyncApi,
      IProtectionEngine engine, byte[] license) throws ExecutionException, InterruptedException {
    PublishingLicenseInfo licenseInfo = PublishingLicenseInfo.getPublishingLicenseInfo(license);
    ConsumptionSettings consumptionSettings = new ConsumptionSettings(licenseInfo);

    if (useAsyncApi) {
      return engine.createProtectionHandlerForConsumptionAsync(consumptionSettings).get();
    } else {
      return engine.createProtectionHandlerForConsumption(consumptionSettings);
    }
  }

  private static void registerContent(boolean useAsyncApi, IProtectionEngine engine, byte[] license, 
      String contentName) throws ExecutionException, InterruptedException {
    PublishingLicenseInfo licenseInfo = PublishingLicenseInfo.getPublishingLicenseInfo(license);

    if (useAsyncApi) {
      engine.RegisterContentForTrackingAndRevocationAsync(licenseInfo, contentName, false).get();
    } else {
      engine.RegisterContentForTrackingAndRevocation(licenseInfo, contentName, false);
    }
  } 

  private static void revokeContent(boolean useAsyncApi, IProtectionEngine engine, byte[] license) throws ExecutionException, InterruptedException {
    PublishingLicenseInfo licenseInfo = PublishingLicenseInfo.getPublishingLicenseInfo(license);
    if (useAsyncApi) {
      engine.RevokeContentAsync(licenseInfo).get();
    } else {
      engine.RevokeContent(licenseInfo);
    }
  } 

  private static IProtectionHandler getProtectionHandlerFromLicense(boolean useAsyncApi,
      IProtectionEngine engine, byte[] license, byte[] preLicense)
      throws ExecutionException, InterruptedException {
    PublishingLicenseInfo licenseInfo = PublishingLicenseInfo
        .getPublishingLicenseInfo(license, preLicense);
    ConsumptionSettings consumptionSettings = new ConsumptionSettings(licenseInfo);

    if (useAsyncApi) {
      return engine.createProtectionHandlerForConsumptionAsync(consumptionSettings).get();
    } else {
      return engine.createProtectionHandlerForConsumption(consumptionSettings);
    }
  }

  private static PreLicenseFormat GetPreLicenseFormat(CommandLine commandLine) {
    if (commandLine.hasOption(CmdOptionsStrings.PRELICENSE_FORMAT)) {
      String value = commandLine.getOptionValue(CmdOptionsStrings.PRELICENSE_FORMAT);

      if (value.equals("Json")) {
        return PreLicenseFormat.Json;
      } else if (value.equals("Xml")) {
        return PreLicenseFormat.Xml;
      } else {
        throw new RuntimeException("Invalid " + CmdOptionsStrings.PRELICENSE_FORMAT + " value of " + value);
      }
    }

    return PreLicenseFormat.Json;
  }

  private static Boolean IsFileXrml(String file) throws IOException {
    String fileData = FileUtils.readFileToString(new File(file), StandardCharsets.UTF_8);
    return Pattern.compile(Pattern.quote("<xrml"), Pattern.CASE_INSENSITIVE).matcher(fileData)
        .find();
  }

  private static String GetDescriptorsAsString(PublishingLicenseInfo publishingLicenseInfo) {
    String retVal = "";
  
    for(LicenseNameAndDescriptionItem descriptor : publishingLicenseInfo.getDescriptor().getDescriptorItems()) {
      retVal += "\n\tLCID: " + String.valueOf(descriptor.getLCID()) + "\tName: " + descriptor.getName() + "\tDescription: " + descriptor.getDescription();
    }
  
    return retVal;
  }
  
  private static String GetSignedAppDataAsString(PublishingLicenseInfo publishingLicenseInfo) {
    String retVal = "";
  
    for(LicenseApplicationData appData : publishingLicenseInfo.getSignedApplicationData()) {
      retVal += "\n\tName: " + appData.getName() + "\tDescription: " + appData.getValue();
    }
  
    return retVal;
  }
  
  private static void PrintPublishingLicenseInfo(PublishingLicenseInfo publishingLicenseInfo) {
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    String issuedTimeString = dateFormat.format(publishingLicenseInfo.getIssuedTime());

    System.out.println("\tExtranetUrl: " + publishingLicenseInfo.getConnectionInfo().getExtranetUrl());
    System.out.println("\tIntranetUrl: " + publishingLicenseInfo.getConnectionInfo().getIntranetUrl());
    System.out.println("\tContentId: " + publishingLicenseInfo.getContentId());
    System.out.println("\tLicenseId: " + publishingLicenseInfo.getDescriptor().getId());
    System.out.println("\tDescriptorCount: " + String.valueOf(publishingLicenseInfo.getDescriptor().getDescriptorItems().size()));
    System.out.println("\tDescriptors: " + GetDescriptorsAsString(publishingLicenseInfo));
    System.out.println("\tIssuedTime: " + issuedTimeString);
    System.out.println("\tIssuerId: " + publishingLicenseInfo.getIssuerId());
    System.out.println("\tOwner: " + publishingLicenseInfo.getOwner());
    System.out.println("\tReferralInfoUrl: " + publishingLicenseInfo.getReferralInfoUrl());
    System.out.println("\tSignedAppDataCount: " + String.valueOf(publishingLicenseInfo.getSignedApplicationData().size()));
    System.out.println("\tSignedAppData: " + GetSignedAppDataAsString(publishingLicenseInfo));
  }

  private static void ParsePublishingLicense(String filePath) throws IOException {
    File inFile = new File(filePath);
    byte[] publishingLicense = FileUtils.readFileToByteArray(inFile);
    PublishingLicenseInfo publishingLicenseInfo = PublishingLicenseInfo.getPublishingLicenseInfo(publishingLicense);
    PrintPublishingLicenseInfo(publishingLicenseInfo);
  }

  private static File FileCheck(String file, String context) {
    File fileToRead = new File(file);
    if (!fileToRead.exists()) {
      throw new RuntimeException(context + " file " + file + " does not exist");
    } else if (fileToRead.isDirectory()) {
      throw new RuntimeException(
        context + " file " + file + " cannot be a directory");
    }

    return fileToRead;
  }

  private static void SaveToFile(String file, byte[] data) throws IOException, FileNotFoundException {
    FileOutputStream outputStream = null;
    DataOutputStream dataOutputStream = null;
    try {
      File outFile = new File(file);
      outputStream = new FileOutputStream(outFile);
      dataOutputStream = new DataOutputStream(outputStream);

      dataOutputStream.write(data);
    } finally {
      if (dataOutputStream != null) {
        dataOutputStream.close();
      }
      if (outputStream != null) {
        outputStream.close();
      }
    }
  }
  
  private static void createDelegationLicense(
      boolean useAsyncApi,
      IProtectionEngine engine,
      String filePath,
      CommandLine commandLine) throws ExecutionException, InterruptedException, IOException {

    if(!commandLine.hasOption(CmdOptionsStrings.USERS)) {
      throw new RuntimeException("You cannot create a delegation license without specifying users");
    }

    String[] users = commandLine.getOptionValue(CmdOptionsStrings.USERS).split(",");

    File file = new File(filePath);
    FileInputStream inputStream = new FileInputStream(file);
    DataInputStream dataInputStream = new DataInputStream(inputStream);
    byte[] publishingLicense = readLicense(dataInputStream);

    PublishingLicenseInfo licenseInfo = PublishingLicenseInfo.getPublishingLicenseInfo(publishingLicense);
    
    List<IDelegationLicense> delegatedLicenses;
    DelegationLicenseSettings delegateLicenseSettings = new DelegationLicenseSettings(licenseInfo, Arrays.asList(users), commandLine.hasOption(CmdOptionsStrings.DELEGATION_END_USER_LICENSE));

    if (useAsyncApi) {
      delegatedLicenses = engine.createDelegationLicensesAsync(delegateLicenseSettings).get();
    } else {
      delegatedLicenses = engine.createDelegationLicenses(delegateLicenseSettings);
    }

    System.out.println("DelegationLicenses:");
    for(IDelegationLicense license : delegatedLicenses) {
      String delegatorLicense;
      try {
        delegatorLicense = Base64.getEncoder().encodeToString(license.getSerializedDelegationJsonLicense());
      } catch (Exception e) {
        delegatorLicense = "Error: " + e.getMessage();
      }

      System.out.print("DelegationLicense User=" + license.getUser());
      System.out.print(" JsonDelegatorLicense=" + delegatorLicense);
      if(delegateLicenseSettings.getAcquireEndUserLicenses()) {
        String jsonLicense;
        String xrmlLicense;
        try {
          jsonLicense = Base64.getEncoder().encodeToString(license.getSerializedUserLicense(PreLicenseFormat.Json));
        } catch (Exception e) {
          jsonLicense = "Error: " + e.getMessage();
        }

        try {
          xrmlLicense = Base64.getEncoder().encodeToString(license.getSerializedUserLicense(PreLicenseFormat.Xml));
        } catch (Exception e) {
          xrmlLicense = "Error: " + e.getMessage();
        }

        System.out.print(" JsonEndUserLicense=" + jsonLicense);
        System.out.print(" XrmlEndUserLicense=" + xrmlLicense);
        
        System.out.println("");
      }
    }
  }

  private static void setRedirections(String redirections, ProtectionProfileSettings profileSetting) {
    String[] allRedirections = redirections.split(";");
    for(String redirection : allRedirections) {
      String[] originalAndRedirect = redirection.split(",");
      if(originalAndRedirect.length != 2) {
        throw new RuntimeException("A redirection must be of the format originalUri;redirectUri");
      }

      profileSetting.addRedirectionUri(originalAndRedirect[0], originalAndRedirect[1]);
    }
  }
}
