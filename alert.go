package main

import "fmt"

func Alert(messageType string) {
	go ExecAndPrint(fmt.Sprintf("%v/alert", LibDir), messageType)
}
