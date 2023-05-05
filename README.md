# YARA-Style-Guide
A specification and style guide for YARA rules

## Introduction 

YARA is a powerful and versatile tool for malware detection, used by security researchers and analysts all over the world. YARA rules are at the heart of this tool, providing a structured way to identify and classify malware based on various characteristics such as file names, sizes, and contents.

Creating effective YARA rules is not an easy task, and it requires a deep understanding of the malware landscape, as well as knowledge of YARA's syntax and capabilities. To help security professionals create high-quality and efficient YARA rules, we have created this style guide.

This guide will cover the best practices for YARA rule structure and contents, including recommendations for naming conventions, syntax, and content selection. By following these guidelines, you will be able to create YARA rules that are accurate, concise, and easy to read and maintain.

Whether you are a seasoned security professional or just getting started with YARA, this guide will provide you with the tools you need to create effective malware detection rules.

## Rule Structure

```yara
rule 
```

## Rule Name

The rule name is sometimes the only or first piece of information that is shown to a user. Therefore it should already include information about the type of threat, tags that classify the threat, a descriptive identifier and even an information about the context or a period in which the rule was created. 

The different values are separated by an underscore character (`_`). 

The values are ordered from generic to specific.

The most generic values are the category of the threat. The following list contains the most common generic classifiers.

### Main Categories

- **MAL** (malware): used for malware
- **HKTL** (hacktool): used for hack tools
- **WEBSHELL**: used for web shells
- **EXPL** (exploit): used for exploit codes (e.g., proof-of-concept code, exploit payloads etc.)
- **VULN** (vulnerability): used for vulnerabilities (e.g., a vulnerable driver, a vulnerable JAVA library etc.)
- **SUSP** (suspicious): used for all kinds of anomalies, suspicious capabilities (e.g., obfuscated code, shell codes, suspicious combination of imports, suspicious set of commands in a script etc.)

Other categories that proofed to be useful when classifying YARA rules:

Important: the lists are not exhaustive and can be extended at any time if necessary. 

### Intention / Background

- **APT** (advanced persistent threat): used to indicate that the 
- **CRIME** (crime group activity): 
- **ANOMALY** (generic and suspicious characteristics)
- **RANSOM**

### Types of Malware

- **RAT**
- **Implant**
- **Stealer**
- **Loader**
- **Crypter**

### Operating System

- **WIN** (often omitted)
- **LNX**
- **MacOS**

### Architecture

- **X64** (often omitted)
- **X86** (often omitted)
- **ARM**
- **AIX**
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

### Other Often Used Tags

- **TINY** : used for very small files
- **HUGE** : used for very big files
- **UAC_Bypass**
- **Base64**

### Uniqueness Suffixes

The suffixes lower the chances that two analysts choose the same rule name by adding values to the rule.

The recommended values are:

- **MonthYear** : e.g., `May23`, `Jan19`
- **Number** : e.g., `*_1`, `*_2`

### Combining the Categories

The mentioned tags are combined to create more specific classification.

Here are some examples:

- `SUSP_APT_*`: used for forensic artifacts found on systems compromised by a threat actor (e.g., hack tool outputs, command line flag combinations, redirected standard outputs, log file contents etc.)
- `MAL_CRIME_RANSOM_LNX_Rust_*` : used for malware used by ransomware crime groups written in Rust for the Linux platform
- `WEBSHELL_APT_ASP_*` : used for ASP webshell used by nation state threat actors 

### Full Rule Name Examples

- `APT_MAL_CozyBear_ELF_Loader_Apr18` : Rule written in April 2018 for a loader used by the threat actor Cozy Bear written for the Linux platform. 
- `SUSP_Anomaly_LNK_Huge_Apr22` : Rule written in April 2022 for suspiciously big link files
- `MAL_CRIME_RANSOM_PS1_OBFUSC_Loader_May23` : Rule written in May 2023xw for an obfuscated PowerShell loader noticed in a Ransomware campaign

## Rule Tags


## Rule Meta Data


## Rule Strings


## Rule Condition


