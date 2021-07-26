# MIP SDK Java Wrapper Sample

This application demonstrates a very basic MIP SDK Java wrapper sample. We can create & retrieve label information from Windows 365.
 
## Features

This project framework provides the following features:

* User authentication
* List Labels
* Apply Label
* Read Label
* Read Protection Information

## Getting Started

### Prerequisites

- Windows 10 or Ubuntu 18.04
- [MIP SDK Java Wrapper - 1.9.xx Preview](https://aka.ms/mipsdkbins)
- MIP SDK (not installed on Windows home version), no need to installed on laptop but requires installation on VM.

### Usage:

 * -c,  --datastate <arg>                     State of the content, REST by default
    * --clientid <arg>                      Sets ClientID for authentication
    * --contentFormat <arg>                 Content format like email etc.
    * --contentFormats <arg>                The list of content formats like email,file etc.
 
 * -d,--delete                              Delete existing label from the given file
   * --DisableFunctionality <arg>          List of functionality to disable
   * --enable_msg                          Enable msg file operations, labelling is not supported for
                                          msg files
   * --enableAuditDelegateOverride <arg>   Enable audit delegate override
   * --EnableFunctionality <arg>           List of functionality to enable
   * --exportpolicy <arg>                  Set path to export downloaded policy to
   * --exportsensitivitytypes <arg>        Set path to export downloaded sensitivity types to
   * --extendedkey <arg>                   Set an extended property key
   * --extendedvalue <arg>                 Set the extended property value
 * -f,--file <arg>                          File path
 * -g,--get                                 Gets the labels and protection of the given file
    * --inspect                             (Optional) Inspect file, doesn't unprotect / protect just
                                          views information about the file.
 * -j,--justification <arg>                 Justification message to applied on set or remove label
 * -l,--list                                Gets all available labels with their ID values
   * --listSensitivityTypes                Gets all available custom sensitivity types for the tenant
 * -p,--protect                             Protects the given file with custom permissions, according
                                          to given lists of users and rights
    * --password <arg>                      Sets password for authentication
    * --policy <arg>                        Sets policy path to local policy file
    * --policybaseurl <arg>                 Cloud endpoint base url for policy operations (e.g.
                                          dataservice.protection.outlook.com)
    * --privileged                          The label will be privileged label and will override any
                                          label
    * --protectionbaseurl <arg>             Cloud endpoint base url for protection operations (e.g.
                                          api.aadrm.com)
    * --protectiontoken <arg>               ProtectionToken authentication
    * --rights <arg>                        Comma-separated list of rights
 * -s,--set <arg>                           Sets label by id
    * --scctoken <arg>                      SccToken authentication
 * -u,--unprotect                           Removes protection from the given file
    * --username <arg>                      Sets username for authentication
    * --users <arg>                         Comma-separated list of users
    * --useStorageCache                     (Optional) Profile uses a to cache engines.
    * --useStreamApi                        Use stream based APIs for input/output.
