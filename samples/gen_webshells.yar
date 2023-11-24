import "math"
// only needed for debugging of module math:
//import "console"

rule WEBSHELL_ASP_OBFUSC
{
    meta:
        description = "ASP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "ad597eee256de51ffb36518cd5f0f4aa0f254f27517d28fb7543ae313b15e112"
        hash = "e0d21fdc16e0010b88d0197ebf619faa4aeca65243f545c18e10859469c1805a"
        hash = "54a5620d4ea42e41beac08d8b1240b642dd6fd7c"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"
        hash = "be2fedc38fc0c3d1f925310d5156ccf3d80f1432"
        hash = "3175ee00fc66921ebec2e7ece8aa3296d4275cb5"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

    strings:
        $asp_obf1 = "/*-/*-*/" wide ascii
        $asp_obf2 = "u\"+\"n\"+\"s" wide ascii
        $asp_obf3 = "\"e\"+\"v" wide ascii
        $asp_obf4 = "a\"+\"l\"" wide ascii
        $asp_obf5 = "\"+\"(\"+\"" wide ascii
        $asp_obf6 = "q\"+\"u\"" wide ascii
        $asp_obf7 = "\"u\"+\"e" wide ascii
        $asp_obf8 = "/*//*/" wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_obfuscation_multi
        // many Chr or few and a loop????
        //$loop1 = "For "
        //$o1 = "chr(" nocase wide ascii
        //$o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o4 = "\\x8" wide ascii
        $o5 = "\\x9" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        //$o10 = " & \"" wide ascii
        //$o11 = " += \"" wide ascii
        // used for e.g. "scr"&"ipt"

        $m_multi_one1 = "Replace(" wide ascii
        $m_multi_one2 = "Len(" wide ascii
        $m_multi_one3 = "Mid(" wide ascii
        $m_multi_one4 = "mid(" wide ascii
        $m_multi_one5 = ".ToString(" wide ascii

        /*
        $m_multi_one5 = "InStr(" wide ascii
        $m_multi_one6 = "Function" wide ascii

        $m_multi_two1 = "for each" wide ascii
        $m_multi_two2 = "split(" wide ascii
        $m_multi_two3 = " & chr(" wide ascii
        $m_multi_two4 = " & Chr(" wide ascii
        $m_multi_two5 = " & Chr (" wide ascii

        $m_multi_three1 = "foreach" fullword wide ascii
        $m_multi_three2 = "(char" wide ascii

        $m_multi_four1 = "FromBase64String(" wide ascii
        $m_multi_four2 = ".Replace(" wide ascii
        $m_multi_five1 = "String.Join(\"\"," wide ascii
        $m_multi_five2 = ".Trim(" wide ascii
        $m_any1 = " & \"2" wide ascii
        $m_any2 = " += \"2" wide ascii
        */

        $m_fp1 = "Author: Andre Teixeira - andret@microsoft.com" /* FPs with 0227f4c366c07c45628b02bae6b4ad01 */
        $m_fp2 = "DataBinder.Eval(Container.DataItem" ascii wide


        //strings from private rule capa_asp_obfuscation_obviously
        $oo1 = /\w\"&\"\w/ wide ascii
        $oo2 = "*/\").Replace(\"/*" wide ascii

    condition:
        filesize < 100KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and
        ( (
        (
            filesize < 100KB and
            (
                //( #o1+#o2 ) > 50 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
            )
        ) or (
            filesize < 5KB and
            (
                //( #o1+#o2 ) > 10 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 5 or
                (
                    //( #o1+#o2 ) > 1 and
                    ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 3
                )

            )
        ) or (
            filesize < 700 and
            (
                //( #o1+#o2 ) > 1 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 3 or
                ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 2
            )
        )
        )
        or any of ( $asp_obf* ) ) or (
        (
            filesize < 100KB and
            (
                ( #oo1 ) > 2 or
                $oo2
            )
        ) or (
            filesize < 25KB and
            (
                ( #oo1 ) > 1
            )
        ) or (
            filesize < 1KB and
            (
                ( #oo1 ) > 0
            )
        )
        )
        )
        and not any of ( $m_fp* )
}

