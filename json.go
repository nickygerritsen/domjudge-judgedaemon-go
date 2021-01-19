package main

import "encoding/json"

func JsonDecode(data []byte, v interface{}) {
	err := json.Unmarshal(data, v)
	if err != nil {
		Error("Error decoding JSON data '%v': %v", string(data), err.Error())
	}
}
