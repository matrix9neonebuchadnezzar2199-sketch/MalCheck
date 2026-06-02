rule example_pe
{
    meta:
        description = "Example — PE MZ header"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}
