# EntropyCapture

EntropyCapture is a simple standalone DLL that when injected into a process that is setting the targeted field will perform the API hooking, grab the entropy and save them to a file.  

An aggressor script is used to monitor for the provided process name and inject shellcode into the process. The shellcode was produced by converting the DLL using the sRDI project (https://github.com/monoxgas/sRDI). When enabled, EntropyCapture will retrieve a process list every 5 seconds, search for the provided application name, and then inject into it.

When the aggressor script is loaded in Cobalt Strike, three new commands will be available:

* start_entropyCapture – Starts checking for the stated process and injects into them.
* stop_entropyCapture – Stops checking but will not unload the already loaded DLL.
* show_entropyCapture – Prints the contents of the file showing captured entropy.

## Screenshot

![Example Usage](images/screenshot.png)

