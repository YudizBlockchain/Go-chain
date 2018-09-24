package main

import (
	"fmt"
)

func main() {

	data := map[string][]int{"Prateek": {1, 2, 3}, "Yash": {2, 5, 6}, "Mahesh": {3, 8, 9}}

	for i := range data {

		fmt.Println(i, data[i])

	}

}
