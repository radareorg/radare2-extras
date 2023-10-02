rule HelloWorld : foo {
        meta:
                author = "pancake"
                description = "hello world"
                date = "2023-10"
                version = "0.1"
        strings:
		$ = "lib"
	condition:
		all of them
}
