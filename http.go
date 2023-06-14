package main

import (
	"fmt"
	"net/http"
)

func hello(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "hello porra\n")
}

func headers(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "%v\n", req.Header["Accept"].(string))

}

func main() {

	http.HandleFunc("/hello", hello)
	http.HandleFunc("/headers", headers)

	http.ListenAndServe(":8090", nil)
}
