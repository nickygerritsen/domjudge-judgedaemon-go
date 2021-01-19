package main

import (
	"fmt"
	"os"
)

func Version() {
	fmt.Printf("%v -- part of DOMjudge version %v\n", scriptId, DomjudgeVersion)
	fmt.Printf("Written by the DOMjudge developers\n\n")
	fmt.Printf("DOMjudge comes with ABSOLUTELY NO WARRANTY.  This is free software, and you\n")
	fmt.Printf("are welcome to redistribute it under certain conditions.  See the GNU\n")
	fmt.Printf("General Public Licence for details.\n")
	os.Exit(0)
}
