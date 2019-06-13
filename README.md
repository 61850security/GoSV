# GoSV

Installation

This process has been tested on Linux platform. Most steps only need to be completed once. 

The program requires ubuntu to be installed followed by GCC compiler and wireshark.  
Then modify the c program with custom values. Specify the network adapter name in the program. save and run with the following commands.

step 1: Change the home directory to your shell environment. 
        To do this just type sudo <your default system shell name>
        for Eg. sudo bash ( in case of bash shell )
step 2: Complie the program.
        cc <filename>.c -o GoSV
step 3: execute the program by sending network adapter name as a commandline arguement. or you can execute directly by    
        ./GoSV  

Step 4: capture the generated packets using wireshark. 

Step 5: The generated packets can also be captured by lib61850 receiver program in Linux platform and infotech SAV receiver program in windows platform
   

For S-GoSV library: Part -1 - RSA digital signatures and MAC implementations, visit https://github.com/61850security/S-GoSV-part-1

   S-GoSV library: Part -2 - Authenticated Encryption (AEAD), visit https://github.com/61850security/S-GoSV
