Eagles-X
=============

Eagle-X ported to Go language from Python. 

The main difference from Python version layed in Golang architecture for concurrency: the goroutines. eagles.py runs
a new thread for each connection in the connection pool so it uses hundreds and thousands of threads. 
eagles.go just uses lightweight goroutines that used only tens of threads (commonly golang runtime started one thread for
CPU core + several service threads). This architecture allows golang version better consume resources and got much higher 
connection pool on the same hardware than Python version can.

This tool targeted for stress testing and may really down badly configured server or badly made app. Use it carefully.

Examples:

    $ eagles -site http://example.com/test/ 2>/dev/null

    $ EAGLESMAXPROCS=4096 eagles -site http://example.com 2>/tmp/errlog



