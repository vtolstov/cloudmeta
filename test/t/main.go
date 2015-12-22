package main

import (
	"log"

	"github.com/antonholmquist/jason"
)

var t = []byte(`
{
    "foo": 1,
    "bar": 2,
    "test": "Hello, world!",
    "baz": 123.1,
    "array": [
        {"foo": 1},
        {"bar": 2},
        {"baz": 3}
    ],
    "subobj": {
        "foo": 1,
        "subarray": [1,2,3],
        "subsubobj": {
            "bar": 2,
            "baz": 3,
            "array": ["hello", "world"]
        }
    },
    "bool": true
}
`)

func main() {
	v, _ := jason.NewObjectFromBytes(t)

	val, err := v.GetInterface("subobj")
	if err != nil {
		panic(err)
	}
	log.Printf("%+v\n", val)
}
