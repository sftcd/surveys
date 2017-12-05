
// count the fields of type foo in a censys report
package main

import (
	"bufio"
	"log"
	"os"
	"fmt"
	"io"
	"encoding/json"
)

func usage(progname string) {
	fmt.Fprintf(os.Stderr,"usage: %v file-name\n",progname)
	os.Exit(1)
}

// read supplied file, line-by-line, decode each line as JSON, count stuff therein
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr,"no file name supplied\n")
		usage(os.Args[0])
	}
	fname := os.Args[1]

	// open file and defer close
    file, foerr := os.Open(fname)
    if foerr != nil {
        log.Fatal(foerr)
    }
    defer file.Close()

	// grab a line at a time and decode, break on any error
    reader := bufio.NewReader(file)
	lineno := 0
	smtps := 0
	nonsmtps := 0
	banners := 0
    var dat map[string]interface{}
    for {
		line, err := reader.ReadString('\n')
		if  err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr,"read error at line %v\n",lineno)
			}
			break
		}
		lineno++
		if err := json.Unmarshal([]byte(line),&dat); err != nil {
			fmt.Fprintf(os.Stderr,"json dcode error at line %v\n",lineno)
			break
		}
		ip := dat["ip"]
		if p25,found := dat["p25"]; found == true {
			smtps++
			fmt.Println(p25)
		} else {
			nonsmtps++
		} 
        fmt.Printf("line %v len = %v for %v\n",lineno,len(line),ip)
		// dump the lot
		//fmt.Println(dat)
    }
	fmt.Printf("Done processing %v with %v lines\n",fname,lineno);
	fmt.Printf("Non-smtp: %v, smtp: %v, banners: %v\n",nonsmtps,smtps,banners)
}
