//dispatcher.c

/*program called dispatcher.c that is going to form two child processes, Amal.c and Basim.c, call exec to execute the programs. Also, create 2 pipes (a-to-b and b-to-a). A-to-B is std out of Amal.c to the write end of a-to-b, then stdin of Basim.c process to the read end of the first pipe. Amal.c will print data through the pipe and Basim will scan data from the pipe. B-to-A will do the opposite. This all done by dispatcher.c*/
