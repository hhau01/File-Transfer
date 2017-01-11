## Usage
	
Open two terminals

Start server:
````
java FileTransfer server private.bin 22222
````

Open client:
````
java FileTransfer client public.bin localhost 22222
````
			
Enter name of file you want to transfer (if in same folder otherwise enter entire directory path):
````
test.txt
````

Enter chunk size (1024 is default):
````
512
````
			
To check for integrity of file use:
````
md5sum test.txt test2.txt
````

Sample output1:

![alt text](https://github.com/hhau01/File-Transfer/blob/master/output1.png "Output 1")

Sample output2:

![alt text](https://github.com/hhau01/File-Transfer/blob/master/output2.png "Output 2")
