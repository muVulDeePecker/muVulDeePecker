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
#include "cgic.h"
#include <string.h>
#include <stdlib.h>

typedef struct cont_t cont;
struct cont_t {
	char data[1024];
};


int cgiMain() 
{
	cont container = {.data=""};
	
	cgiHeaderContentType("text/html");
	/* 
		Top of the page 
	*/
	fprintf(cgiOut, "<html><head>\n");
	fprintf(cgiOut, "<title>Cross-Site Scripting: 1</title></head>\n");
	fprintf(cgiOut, "<body><h1>XSS Test</h1>\n");
	/* 
		If a the parameter 'q' has some data, print it 
	*/
	cgiFormString("q", container.data, sizeof(container.data));
	fprintf(cgiOut, "Value = ");
	cgiHtmlEscape(container.data);							/* FIX */
	/* Finish up the page */
	fprintf(cgiOut, "</body></html>\n");
	return 0;
}
