rule Lab3
{
meta:
	description = "rules for Lab3"
	date = "202x/xx/xx"
strings:
	$a = "vmx32to64" wide ascii
	$b = "serve.html" wide ascii
    $c = "www.practicalmalwareanalysis.com" wide ascii
	$d = "http://www.malwareanalysisbook.com" wide ascii
	$e = "svchost" wide ascii
	$f = "practicalmalwareanalysis.log" wide ascii
condition:
	any of them
}