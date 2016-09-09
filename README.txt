How to run:
	
	Open two terminals:

		Start server:
			java FileTransfer server private.bin 22222

		Open client:
			java FileTransfer client public.bin localhost 22222
			Enter name of file you want to transfer (if in same folder otherwise enter entire directory path)
			Enter chunk size (1024 is default)
			
			To check for integrity of file use:
			md5sum name.txt name2.txt