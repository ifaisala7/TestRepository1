rule ioc_rules {


strings:
	$a = "199d193f31fd7d117070a66e89c4839dddd513b2"
	$b = "419a7631f06ed78a711f18323f5dee882daaa409"
	$c = "635e321bcab27f22e0303da26198ac90381608a4"
	$d = "63632224f977aaaa1c7d88be65cf16878b4bef56"
	$e = "87a14a0464e55581748d3396881aa36a57383132"
conditions:
	($a or $b or $c or $d or $e)
}