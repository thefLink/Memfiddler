# Memfiddler

Executes shellcode from a remote server and aims to evade in-memory scanners

## Description
Memfiddler downloads shellcode from a remote server and executes it in a seperate thread.    

It aims to evade in memory scanners, by periodically suspending this thread and changing all RWX pages to readonly. Additionally,
the pages are 'encrypted'. After a while, the pages are restored and the thread is resumed.

## Usage
Change the following variables to your needs:
- ***ACTIVE_TIME***: Specifies how long the thread is active before hibernating
- ***HIBERNATE_TIME***: Specifes how long the thread is suspended and the memory 'encrypted'
- ***C2***: Location of your shellcode
- ***UA***: You probably want to set it to the UA installed on the endpoint    

Compilation:
```
x86_64-w64-mingw32-g++ Memfiddler.cpp -lwininet -shared -o [somename].dll
```
On the endpoint use your favourite dll loader to execute the export ***go***


### Please Note
- The thread is supended! This means that calls to sleep() will sleep() even longer
- The 'encryption' is not really an encryption. It's sole purpose is to confuse memory scanners.
- Memfiddler does not support shellcode which does multithreaded-foo

