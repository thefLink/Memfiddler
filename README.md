# Memfiddler

Executes shellcode from a remote server and aims to hide it from blue teamers and memory scanners running periodically.     

It is not meant to (and does not) bypass an AV. It's sole purpose is to hide from the blueteam which might be checking the content of RWX pages.     
Whether you are initially flagged or not depends on the shellcode you execute. :-) 

## Description
Memfiddler downloads shellcode from a remote server and executes it in a seperate thread.    

It aims to evade in memory scanners, by periodically suspending this thread and changing all RWX pages to readonly. Additionally, the pages are 'encrypted'. After a while, the pages are restored and the thread is resumed.

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

### Todo
- The shellcode on the network is in cleartext. I should probably add something to change that
