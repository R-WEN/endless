/*
endless provides a drop in  replacement for the `net/http` stl functions `ListenAndServe` and `ListenAndServeTLS` to achieve zero downtime restarts and code upgrades.

The code is based on the excellent post [Graceful Restart in Golang](http://grisha.org/blog/2014/06/03/graceful-restart-in-golang/) by [Grisha Trubetskoy](https://github.com/grisha). I took his code as a start. So a lot of credit to Grisha!

The original endless has been modified to include ListenAndServeTLSWithSNI for name-resoved TLS.   Also a number of defects have been fixed.
*/
package endless
