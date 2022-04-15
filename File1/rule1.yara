rule dummy
{
	strings:
		$a="very tricky"

	condition:
		$a
}