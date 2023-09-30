# YARA-Style-Guide
A specification and style guide for YARA rules

## Introduction 

YARA is a powerful and versatile tool for malware detection, used by security researchers and analysts all over the world. YARA rules are at the heart of this tool, providing a structured way to identify and classify malware based on various characteristics such as file names, sizes, and contents.

Creating effective YARA rules is not an easy task, and it requires a deep understanding of the malware landscape, as well as knowledge of YARA's syntax and capabilities. To help security professionals create high-quality and efficient YARA rules, we have created this style guide.

This guide will cover the best practices for YARA rule structure and contents, including recommendations for naming conventions, syntax, and content selection. By following these guidelines, you will be able to create YARA rules that are accurate, concise, and easy to read and maintain.

Whether you are a seasoned security professional or just getting started with YARA, this guide will provide you with the tools you need to create effective malware detection rules.

## Scope

This YARA Style Guide is primarily focused on enhancing readability, maintainability, and usability of YARA rules. It doesn’t delve into the aspects of performance or resource utilization, although adhering to these best practices can inadvertently lead to optimized rule set performance. (e.g., the order of the expressions in the condition)

For in-depth insights and strategies on performance and resource optimization, we recommend exploring [this project](https://github.com/Neo23x0/YARA-Performance-Guidelines/).

## Rule Names

```yara
rule TBD
```

## Rule Name

The rule name is sometimes the only or first piece of information that is shown to a user. Therefore it should already include information about the type of threat, tags that classify the threat, a descriptive identifier and even an information about the context or a period in which the rule was created. 

The different values are separated by an underscore character (`_`). 

The values are ordered from generic to specific.

The most generic values are the category of the threat. The following list contains the most common generic classifiers.

### Main Categories

- **MAL** (malware) : used for malware
- **HKTL** (hacktool) : used for hack tools
- **WEBSHELL** : used for web shells
- **EXPL** (exploit) : used for exploit codes (e.g., proof-of-concept code, exploit payloads etc.)
- **VULN** (vulnerability) : used for vulnerabilities (e.g., a vulnerable driver, a vulnerable JAVA library etc.)
- **SUSP** (suspicious) : used for all kinds of anomalies, suspicious capabilities (e.g., obfuscated code, shell codes, suspicious combination of imports, suspicious set of commands in a script etc.)
- **PUA** : used for possibly unwanted applications

Other categories that proofed to be useful when classifying YARA rules:

Important: the lists are not exhaustive and can be extended at any time if necessary. 

### Intention / Background

- **APT** (advanced persistent threat): used to indicate that the 
- **CRIME** (crime group activity): 
- **ANOMALY** (generic and suspicious characteristics)
- **RANSOM**

### Types of Malware / File

- **RAT**
- **Implant**
- **Stealer**
- **Loader**
- **Crypter**
- **PEEXE** (often omitted)
- **DRV** : used for drivers

### Operating System

- **WIN** (often omitted)
- **LNX**
- **MacOS**

### Architecture

- **X64** (often omitted)
- **X86** (often omitted)
- **ARM**
- **SPARC**

### Technology

- **PE** (often omitted) / - **ELF**
- **PS** / **PS1** / **VBS** / **BAT** / **JS**
- **NET** / **GO** / **Rust**
- **PHP** / **JSP** / **ASP**
- **MalDoc**
- **LNK**
- **ZIP**
- **RAR**

### Modifiers

- **OBFUSC** : used for obfuscated samples 
- **Encoded** : used for encoded versions of payloads
- **Unpacked** : used for unpacked payloads
- **InMemory** : used for code that can only be found when loaded into memory

### Packers / Installers

- **SFX** : used for self-extracting archives
- **UPX**
- **Themida**
- **NSIS**

### Threat Actor Identifiers

The threat actor identifier tags are straight forward. 

The list only contains examples:

- **APT28**
- **UNC4736**
- **Lazarus**

### Threat Identifiers

The threat identifier tags are straight forward. 

- **CobaltStrike**
- **PlugX**
- **QakBot**

### Other Often Used Keywords

- **TINY** : used for very small files
- **HUGE** : used for very big files
- **UAC_Bypass**
- **Base64**

### Suffixes to Guarantee Uniqueness

The suffixes lower the chances that two analysts choose the same rule name by adding values to the rule.

The recommended values are:

- **MonthYear** : e.g., `May23`, `Jan19`
- **Number** : e.g., `*_1`, `*_2`

### Combining the Categories

The mentioned keywords are combined to create a more specific classification.

Here are some examples:

- `SUSP_APT_*`: used for forensic artifacts found on systems compromised by a threat actor (e.g., hack tool outputs, command line flag combinations, redirected standard outputs, log file contents etc.)
- `MAL_CRIME_RANSOM_LNX_Rust_*` : used for malware used by ransomware crime groups written in Rust for the Linux platform
- `WEBSHELL_APT_ASP_*` : used for ASP webshell used by nation state threat actors 

### Full Rule Name Examples

- `APT_MAL_CozyBear_ELF_Loader_Apr18` : Rule written in April 2018 for a loader used by the threat actor Cozy Bear written for the Linux platform. 
- `SUSP_Anomaly_LNK_Huge_Apr22` : Rule written in April 2022 for suspiciously big link files
- `MAL_CRIME_RANSOM_PS1_OBFUSC_Loader_May23` : Rule written in May 2023xw for an obfuscated PowerShell loader noticed in a Ransomware campaign


## Rule Structure and Values

```yara
rule RULE_NAME : TAGS {
    meta:
        description = "Detects ..."
        author = "Author Name / Company / Org"
        date = "YYYY-MM-DD"
        reference = "URL / Internal Research"
        [OPTIONAL META DATA FIELDS]
    strings:
        $string1 = "value"
    condition:
        header_check
        file_size_limitation
        other_limitations
        string_combinations
        false_positive_filters
}
```


## Indentation

Utilize indentation to enhance the readability of your YARA rules. It's common practice to use either 3 or 4 spaces or tabs for indentation in most published rules. This consistency aids in maintaining a clean and organized presentation of the code, making it easier to read and understand.

DON'T
```
rule MY_RULE {
meta:
description = "my test rule"
author = "John Galt"
strings:
$s1 = "eval("
$s2 = "WScript.Shell"
condition:
filesize < 10KB and all of them 
}

rule MY_RULE {
 meta:
  description = "my test rule"
  author = "John Galt"
 strings:
  $s1 = "eval("
  $s2 = "WScript.Shell"
 condition:
  filesize < 10KB and all of them 
}
```

DO
```
rule MY_RULE {
   meta:
      description = "my test rule"
      author = "John Galt"
   strings:
      $s1 = "eval("
      $s2 = "WScript.Shell"
   condition:
      filesize < 10KB and all of them 
}
```

### Rule Tags

While rule tags can be employed to classify and group related rules together, in this guide, we advise incorporating main categories directly into the rule name for more straightforward identification. Additional tags that are less directly related to the main category should be included in a dedicated meta data field called "tags". This approach keeps rule names concise while also offering the flexibility to include more context-specific tags.

The chapter on the rule names explains how to include main categories in the rule name:

```yara
rule RULE_NAME_MAIN_CATEGORY1_MAIN_CATEGORY2 {
    ...
}
```

For additional, less directly related tags, you can add them to the tags field in the meta data section:

```yara
rule RULE_NAME {
    meta:
        tags = "TAG1, TAG2, TAG3"
    ...
}
```

These tags can denote a variety of attributes such as threat actor names (e.g., APT28, Lazarus), malware families (e.g., Emotet, TrickBot), or types of attacks (e.g., phishing, ransomware). See the chapter on rule names for details.

## Rule Meta Data

The meta section provides additional information about the rule. This can include the author's name, a reference to the research paper or blog post that describes the malware, the date when the rule was written, or any other information that you consider relevant.

```yara
rule RULE_NAME : TAGS {
    meta:
        description = "Detects ..."
        author = "Author Name / Company / Org"
        date = "YYYY-MM-DD"
        reference = "URL / Internal Research"
        score = [0-100]
        [OPTIONAL META DATA FIELDS]
    ...
}
```

As the name suggests, the optional meta fields are not required for the rule to function, but they can provide valuable context to anyone who uses the rule.

### Mandatory Meta Data Fields

Certain meta data fields are indispensable as they contain critical information for analysts who work with the rule or evaluate rule matches.

- `description`: This should provide a clear and succinct description of what the rule is designed to detect.
- `author`: This field specifies the author, group, or organization that composed or released the rule.
- `reference`: This should link to a report, source code repository, website, private report name, identifier, or a short description of the source from which the rule was derived.
- `date`: This denotes the creation date of the rule and should be in the format YYYY-MM-DD.

The following chapters describe the values in more detail. 

#### Description

| Field  | Description                                  |
|--------|----------------------------------------------|
| Value | String |
| Preferred Length | 60-400 characters |
| Avoid | URLs |
| Prefer | Value starts with "Detects ..." |

The "Description" field plays a crucial role in conveying the core intent and scope of a YARA rule. Here's a guide to constructing an effective description:

Preferred Length: It's recommended to keep the description between 60 to 400 characters. This range ensures the description is concise, yet provides enough information for analysts and other users to understand the rule's purpose without overwhelming them.

Avoid URLs: Refrain from including URLs directly in the description. If a reference is necessary, it's better to use the reference meta field or another dedicated field for URLs.

Starting Convention: Start your description with the phrase "Detects ...". This format offers clarity, ensuring users can quickly ascertain what the YARA rule identifies or monitors.

#### Author

| Field  | Description                                  |
|--------|----------------------------------------------|
| Value | String |
| Avoid | URLs |
| Prefer | Full name, Twitter handles |

The "Author" field provides attribution and aids in understanding the provenance of a YARA rule. Here's how to best structure this field:

Preferred Length: There's no strict length guideline for the "Author" field. However, clarity and brevity are always appreciated.

Avoid URLs: Direct URLs shouldn't be placed in the "Author" field. If you need to provide additional information about the author or the source, consider using other meta fields or providing accompanying documentation.

Author Identification: It's best to use the full name of the author for clear attribution. If you want to give credit using a social media identifier, Twitter handles are preferable.

Multiple Authors: If a rule is a result of collaborative work, instead of using the "Author" field multiple times, consolidate the authors into a single field using a comma-separated list. This ensures the meta section remains tidy and concise.

#### Reference

| Field  | Description                                  |
|--------|----------------------------------------------|
| Value | List of Strings |
| Avoid | Unstable links, links to private resources |
| Prefer | URLs |

The "Reference" field is crucial for providing context and background information regarding the YARA rule. Here's a guide to populating this field optimally:

What Can a Reference Be? A reference can be a direct link to a report from which the YARA rule was derived, copied, or where the specific rule can be found. This provides clarity on the rule's origins and its foundational evidence.

Preferred Length: While there isn't a hard limit on the length for the "Reference" field, it's essential that any references provided are concise and directly relevant.

Avoid Unstable Links and Private Resources: It's best not to include URLs that might become inactive in the near future, rendering the reference useless. Additionally, links that lead to private, restricted, or paywalled resources should be avoided, as they may not be accessible to all users.

Preference for URLs: When providing references, it's optimal to use direct URLs that lead to public and stable sources of information, such as research papers, blog posts, or official advisories.

Internal Work: If the YARA rule is derived from your own research, ideas, or observations rather than from external publications, it's appropriate to use "Internal Research" as the value for the reference. This indicates that the rule's origin is proprietary and not directly linked to an external public source.

#### Date

| Field  | Description                                  |
|--------|----------------------------------------------|
| Value | List of Strings |
| Preferred Format | YYYY-MM-DD |

The "Date" field serves as a crucial indicator of when a YARA rule was initially formulated. This timestamp is essential to understand the context and timing of the rule's creation. Here's how you can optimally populate this field:

Format Requirement: When inputting the date for your rule, ensure that you use the format "YYYY-MM-DD". This standardized format ensures consistency across all rules and ease of understanding for analysts and researchers.

Reflecting the Creation Date: It's essential to note that the "Date" field should exclusively indicate when the rule was originally created. It is not meant to showcase when the rule was published or any subsequent modifications made to it.

Modifications: If you make any changes to a YARA rule after its original creation, you should indicate this in a separate field named "modified". This distinction ensures clarity about the rule's original inception and any updates that may have been made subsequently.

### Optional Meta Data Fields

While mandatory meta data fields provide essential information about a YARA rule, optional fields offer supplementary details that can further enhance the context, functionality, and traceability of the rule. They're particularly useful for providing additional search parameters, recording changes, and maintaining rule versioning.

- `hash`: This field can hold one or more MD5, SHA1, SHA256 values. You can use the hash field multiple times if needed. It can be a list of hash values. The SHA256 hash is the preferred value. 
- `score`: A numerical score between 0 and 100, which is used to represent a combination of the rule's severity (how critical the threat it identifies is) and specificity (how uniquely the rule identifies a particular threat). The score can aid in prioritizing responses to rule matches, e.g. rules with higher score are more critical. 
- `modified`: This specifies the last modification date of the rule, which is useful when the rule gets updated post its initial creation. The date should be in the YYYY-MM-DD format.
- `old_rule_name`: This is used to hold the previous name of the rule. It allows for searches using the old name in case the name has been changed.
tags: This is used to include a list of tags. Each tag should be separated by a comma.
- `license`: A license under which the rule has been released.

#### Hash 

| Field  | Description                                  |
|--------|----------------------------------------------|
| Value | List of Strings |
| Avoid | N/A |
| Prefer | SHA256 hash |

The "Hash" field in a YARA rule is integral to the detection process, as it provides a distinct identifier for the file to be matched. Properly populating this field ensures optimal rule execution and precise matching. Here are some guidelines to consider:

Hash Type: While you might encounter various hash types, it's preferable to use the SHA256 hash. It offers a higher level of specificity and reduces the likelihood of collisions compared to some other hash types.

Direct File Reference: The hash should directly correlate to the file that the YARA rule is intended to match. This ensures that the rule effectively detects the intended threat without false positives.

Avoid Archive Hashes: It's essential to avoid using hashes of archives where the sample might have been found. Instead, focus on the extracted file or the malicious content itself. By doing so, you ensure that the detection is specific to the threat and not the container it might have come in.

Exception for Memory-based Matches: An exception to the above is when your rule is designed to detect samples loaded into memory. In scenarios where the rule might not detect a sample on disk but identifies the unpacked, unencrypted, or loaded sample in memory, the hash related to that memory form should be used.

#### Score 

| Field  | Description                                  |
|--------|----------------------------------------------|
| Value | Number|
| Range | 0-100 |

The "Score" field in a YARA rule plays a pivotal role in gauging the potential impact and uniqueness of a detected threat. This field incorporates two key dimensions: the severity of the detected threat and the specificity of the rule in identifying it. Here's a breakdown of what you should know:

Value Range: The score is a numerical value ranging between 0 and 100. It's not just an arbitrary number; it offers an insight into the potential risks associated with a rule match.

Severity and Specificity: This score embodies two essential characteristics:

Severity: It indicates how critical or detrimental the detected threat is. A high severity score points to potentially significant damage or impact if the threat is not addressed.
Specificity: It tells you how uniquely the rule identifies a particular threat, ensuring that it's not just catching benign or unrelated items.
Response Prioritization: One of the most significant utilities of the score is in threat response prioritization. When inundated with numerous rule matches, security analysts can prioritize responses based on the score. A higher score typically suggests that the rule match is more critical and should be addressed with higher urgency.

Incorporating a well-thought-out score in your YARA rules ensures a more strategic and effective approach to threat detection and response.

Use this table as a guideline to assign a score, ensuring that your rule appropriately represents the threat level:

| Score Range | Significance Level                         | Examples & Use Cases                                                           |
|-------------|--------------------------------------------|--------------------------------------------------------------------------------|
| 0-39        | Very Low Significance                      | Capabilities, packers etc. (often combined for a higher total score)            |
| 40-59       | Noteworthy                                 | Uncommon packers or those often used by malware, PE header anomalies            |
| 60-79       | Suspicious                                 | Heuristics matches, obfuscation rules, generic detection rules                  |
| 80-100      | High (Direct matches on malware/hack tools)| Malware, hack tools, and other malicious entities identified with high accuracy |

## Rule Strings

The strings section of a YARA rule specifies the sequences of bytes, strings, or regular expressions that will be searched for within the file. Each string is given a unique identifier that can be used in the condition section to refer to the string.

```yara
rule RULE_NAME {
    ...
    strings:
        $s1 = "value"
        $s2 = { E2 34 F1 67 }
        $r1 = /abc[def]+/
    ...
}
```

In the example above, `$s1` is a simple string, `$s2` is a sequence of bytes, and `$r1` is a regular expression.

### String Identifiers

There are some best practices in regards to the use of string values in YARA.

Opt for Readable String Values
For enhanced readability, avoid using hexadecimal representation for string values that can be effectively represented with standard strings. Exceptions to this rule include strings containing control characters like \t (tab) or \n (newline), where the hexadecimal format is preferred.

Avoid:

```yara
$s1 = { 46 72 6F 6D 42 61 73 65 36 34 53 74 72 69 6E 67 28 }
```

Recommended:

```yara
$s1 = "FromBase64String("
```

#### Choose Efficient String Identifiers

Opt for concise or descriptive identifiers for strings to enhance the readability of your YARA rules. Avoid long, non-descriptive identifiers, as they can clutter the code and make conditions, especially complex ones, difficult to read and understand.

Avoid:

```yara
   $string_value_footer_1 = "eval("
   $selection_14 = "eval("
...
condition:
   all of (selection_*) and 3 of ($string_value_footer)
```
Recommended:

```yara
   $s1 = "eval("
   $eval = "eval("
condition:
   all of (s*) and $eval
```

Incorporating these practices ensures your YARA rules are not only functional but also user-friendly, fostering an environment of efficiency and collaboration among security professionals.

### Hex Identifiers

For hexadecimal representations that primarily consist of ASCII characters, it’s helpful to include the ASCII string representation or the readable portions thereof in a comment, enhancing understandability.

```yara
   /* )));\nIEX( */
   $s1 = { 29 29 29 3b 0a 49 45 58 28 0a }
```

To enhance readability, it's advisable to segment hex identifiers at every 16-byte interval. This practice is particularly beneficial for lengthy values, allowing observers to quickly gauge the length of the value without the need to horizontally scroll through the code.

```yara
   $s1 = { 2c 20 2a 79 6f 77 2e 69 20 26 20 30 78 46 46 29 
           3b 0a 20 20 70 72 69 6e 74 66 20 28 28 28 2a 79 
           6f 77 2e 69 20 26 20 30 78 66 66 29 20 3d 3d 20 
           30 78 34 31 29 20 3f 20 22 4c 49 54 54 4c 45 5c 
           6e 22 20 3a 20 22 42 49 47 5c 6e 22 29 3b 0a 20 
           20 70 72 69 6e 74 66 20 28 22 73 68 6f 72 74 20 
           25 64 3b 20 20 69 6e 74 }
```

## Rule Condition

The condition section of a YARA rule specifies the conditions that must be met for the rule to be considered a match. This is where the magic of YARA really happens. Conditions can be simple or complex, combining multiple strings, byte sequences, and metadata checks.

```yara
rule RULE_NAME : TAGS {
    ...
    condition:
        header_check
        file_size_limitation
        other_limitations
        string_combinations
        false_positive_filters
}
```

In the example above, the condition would be met if the checks in header_check, file_size_limitation, other_limitations, string_combinations and false_positive_filters are true. It's important to write conditions in a way that optimizes performance, especially when dealing with large data sets or live traffic.

Remember, the conditions should reflect the detection logic of your rule, be it based on the presence of certain strings, file size restrictions, or other characteristics that define your target threat. Be cautious while defining conditions, as too broad or too lenient conditions might lead to a high number of false positives.

### Examples

```yara
rule RULE_NAME : TAGS {
    ...
    condition:
        uint16(0) == 0x5a4d 
        and filesize < 300KB 
        and pe.number_of_signature == 0
        and all of ($s*)
        and not 1 of ($fp*)
}
```

For improved clarity, it's advised to place a new line before the and keyword. Experience has demonstrated that this approach enhances readability, making rules quicker to understand.

When parts of the condition need to be combined using an or operator, it's recommended to encapsulate these components within an indented block:

```yara
rule RULE_NAME : TAGS {
    ...
    condition:
        uint16(0) == 0x5a4d 
        and filesize < 300KB 
        and pe.number_of_signature == 0
        and (
            1 of ($x*)
            or 3 of them
        )
        and not 1 of ($fp*)
}
```

```yara
rule RULE_NAME : TAGS {
    ...
    condition:
        uint16(0) == 0x5a4d 
        and filesize < 300KB 
        and (
            1 of ($x*)
            or (
                2 of ($s*) 
                and 3 of them
            )
        )
}
```

For conditions that require the evaluation of multiple potential values, such as different file markers, the same indented block format should be applied:

```yara
rule RULE_NAME : TAGS {
    ...
    condition:
        (
            uint16(0) == 0x5a4d     // MZ marker
            or uint16(0) == 0x457f  // ELF marker
        )
        and filesize < 300KB 
        and pe.number_of_signature == 0
        and all of ($s*)
        and not 1 of ($fp*)
}
```

Adhering to this format fosters easy readability and promotes a clean, structured presentation of the rule conditions.

## Sometimes Performance Trumps Readability

### String Matching FTW

It’s not uncommon for some to leverage looping and hashing techniques to identify patterns within the PE headers of files, as illustrated below. In this example, the author iteratively calculates the MD5 hash of the initial 100 bytes of code across all PE sections and contrasts it with a predetermined hash value.

```yara
   condition:
      for any var_sect in pe.sections:
         (hash.md5( var_sect.raw_data_offset, 0x100 ) == "d99eb1e503cac3a1e90450d0c07e3ffc" )
```

However, this approach is less efficient than it might initially appear. YARA is intrinsically designed for direct string and pattern matching, making it highly efficient in these tasks. Conversely, cycling through each section and calculating hashes can be resource-intensive and less optimal.

A more streamlined and efficient approach is to directly incorporate the 100 bytes as a hexadecimal string within the YARA rule. This modification bypasses the computational overhead of hashing and leverages YARA's innate efficiency in string matching, ensuring rapid and precise detection without unnecessary CPU consumption.
