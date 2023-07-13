package main

import (
	"fmt"
	"strings"
)

// This package doesn't use any of the code in M, but instead
// is used to build something or as a helper

func main() {
	s := strings.Join([]string{"One", "Two"}, " ")
	fmt.Println(s)
}
