
rule LOG_F5_BIGIP_Exploitation_Artefacts_CVE_2021_22986_Mar21_1 : LOG {
   meta:
      description = "Detects forensic artefacts indicating successful exploitation of F5 BIG IP appliances as reported by NCCGroup"
      reference = "https://research.nccgroup.com/2021/03/18/rift-detection-capabilities-for-recent-f5-big-ip-big-iq-icontrol-rest-api-vulnerabilities-cve-2021-22986/"
      status = "experimental"
      my_bogus_date = "01.01.2020"
      id = "ab48d370af123"
   strings:
      $x1 = "\",\"method\":\"POST\",\"uri\":\"http://localhost:8100/mgmt/tm/util/bash\",\"status\":200," ascii
      $x2 = "[com.f5.rest.app.RestServerServlet] X-F5-Auth-Token doesn't have value, so skipping" ascii
   condition:
      1 of them
}

rule SUSP_ThemeBleed_Theme_Sep23 {
    meta:
        description = "Detects domain or IP placement in Windows theme files"
        author = "@m_haggis, @nas_bench"
        reference = "https://github.com/gabe-k/themebleed"
        score = 75

    strings:
        $s1 = /Path=\\\\[0-9a-zA-Z\.-]{1,20}\\/
        $s2 = "[VisualStyles]"
        $s3 = "[Theme]"

    condition:
        filesize < 1MB and all of them
}

rule SUSP_Bad_Regex_Sep23 {
    meta:
        description = "Detects a bad regex"
        author = "Noob"
        reference = "https://github.com/gabe-k/themebleed"
        score = 75
    strings:
        $sr1 = /[\w\-.]{1,3}@[\w\-.]{1,3}/
    condition:
        $sr1
}

