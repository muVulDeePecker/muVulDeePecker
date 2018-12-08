
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



#include <iostream>
using namespace std;

int main()
{
	char *buf;
	char *t;
	unsigned i;
        unsigned length;

	buf = new (nothrow) char[25];
	if (buf == 0){cout << "Error: memory could not be allocated"; return 0;}
  	
        srand(time(NULL));
	length = rand() % 50 + 1;
        t = new (nothrow) char[length];
	if (t == 0){cout << "Error: memory could not be allocated"; return 0; }
	
	for (i=0;i<45;i++)t[i] = (char)((rand() % 26)  + 'a');
        t[i+1] = '\0';
        buf[strlen(t)]=t[strlen(t)-1];

	
	delete [] t;
        delete [] buf;

	return 0;
}
