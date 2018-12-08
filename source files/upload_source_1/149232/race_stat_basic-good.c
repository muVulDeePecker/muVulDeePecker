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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

const char fName[] = "test.file";
const char string[] = "What I want to write";

void handler(int curPid)
{
	int fd;
	struct stat fileStat;
	fprintf (stdout, "(%d) Start handler...\n",curPid);

	if ((fd = open(fName, O_WRONLY | O_CREAT | O_EXCL)) != -1) /* FIX */
	{
		// checks for file information safely
		if(fstat(fd, &fileStat) == 0)
        {
        	if(fileStat.st_size > 2048)
            {
                fprintf(stderr, "(%d) File is larger than 2k\n", curPid);
            }
            else
            {
              	char output[BUFSIZ];
      			sprintf(output, "(%d) %s", curPid, string);
            	if(write(fd, output, strlen(output) * sizeof *output) < strlen(output) * sizeof *output)
					fprintf (stderr, "(%d) Couldn't write all characters\n", curPid);
            } 
        }

		close(fd);
	}  
  	else 
    {
    	if (errno == EEXIST) 
          	fprintf(stderr, "(%d) File exists\n", curPid);
        else if (errno == EACCES) 
          	fprintf(stderr, "(%d) Requested access not allowed\n", curPid);
    }
	// send the message to the child which should be in fork
	fprintf (stdout, "(%d) Stop handler...\n",curPid);
}

int main(int argc, char *argv[])
{
	unsigned i;
	pid_t pid = 0;
	// create fork 1
	if (fork())
		return 0;
	
	for (i=0;i<3;++i) {
		pid = fork();
		if (pid == 0)
		{
			pid = getpid();
			printf ("Run: %d\n",pid);
			handler(pid);
			break;
		}
	}
	return 0;
}
