/* This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of their
 * official duties. Pursuant to title 17 Section 105 of the United States
 * Code this software is not subject to copyright protection and is in the
 * public domain. NIST assumes no responsibility whatsoever for its use by
 * other parties, and makes no guarantees, expressed or implied, about its
 * quality, reliability, or any other characteristic.

 * We would appreciate acknowledgement if the software is used.
 * The SAMATE project website is: http://samate.nist.gov
*/

/*
	Simple case: Enter a file as input and dislay it
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char **fileNames = NULL;

int printFile(const char *fileName)
{
	FILE *fp = (FILE *)NULL;
	if ((fp = fopen(fileName, "r")))
	{
		char buffer[512];
		unsigned int lNumber = 0;
		printf (">>> %s\n",fileName);
		while (fgets(buffer, 512, fp))
		{
			printf("%3d: %s", ++lNumber, buffer);
		}		
		fclose(fp);
		return 0;
	}
	return 1;
}


int main(int argc, char *argv[])
{
	short badAlloc = 0;
	// Open the file in the command line
	if (argc > 1)
	{
		const unsigned int nbArgs = argc - 1;
		if ((fileNames = (char **)malloc((nbArgs) * sizeof(char **))) == NULL)
			return 0;		
		for (unsigned int i=0;i<nbArgs;++i)
		{
			// allocate the direction
			if (!(fileNames[i] = (char *)malloc(256 * sizeof(char))))
				badAlloc = 1;
			else
				strncpy(fileNames[i], argv[i+1], 255);
		}
		
		if (!badAlloc)
		{
			for (unsigned int i=0;i<nbArgs;++i)
				if (printFile(fileNames[i]))
					printf("Argument error, the given argument is not a readable file (%s).\n", fileNames[i]);
		}
		
		for (unsigned int i=0;i<nbArgs;++i)
			free(fileNames[i]);
		free(fileNames);
	}
	return 0;	
}
