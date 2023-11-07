rule Broken_Rule {
  meta:
    description = "This is a broken rule"
    author = "Florian Roth"
  strings:
    $a1 = "this is a test"
    $a2 = "another string for the test"
  condition:
    3 of them
}
