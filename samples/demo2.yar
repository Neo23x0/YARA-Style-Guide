
rule HKTL_EXPL_POC_LibSSH_Auth_Bypass_CVE_2023_2283_Jun23_1 {
   meta:
      description = "Detects POC code used in attacks against libssh vulnerability CVE-2023-2283"
      author = "Florian Roth"
      date = "2023-06-08"
      score = 85
   strings:
      $s1 = "nprocs = %d" ascii fullword
      $s2 = "fork failed: %s" ascii fullword
   condition:
      uint16(0) == 0x457f and all of them
}
