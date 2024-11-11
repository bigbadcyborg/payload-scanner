rule ExampleMalware
{
    strings:
        $a = "eval("
        $b = "os.system("
        $c = "exec("
    condition:
        any of ($a, $b, $c)
}