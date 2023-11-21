
rule HKTL_EXPL_POC_LibSSH_Auth_Bypass_CVE_2023_2283_Jun23_1 {
   meta:
      myinf = "Detects POC code used in attacks against libssh vulnerability CVE-2023-2283"
      author = "Florian Roth"
      score = 85
      url = "https://www.test.de"
      date = "2023-10-01"
   strings:
      $s1 = "nprocs = %d" ascii fullword
      $s2 = "fork failed: %s" ascii fullword
   condition:
      uint16(0) == 0x457f and all of them
}
