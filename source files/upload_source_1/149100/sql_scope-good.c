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
#include <mysql/mysql.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <stdint.h>


/* Replacement to memset() that cannot be optimized out */
char *my_memset_s(char *s, int c, size_t n)
{
	volatile char *p = s;

	if(p != NULL)
		while (n--)
			*p++ = c;

	return s;
}

/* Reads a password from a terminal - replaces obsolete getpass() function */
char * getpass_r(const char *prompt)
{
	struct termios oflags, nflags;
	char password[64] = { '\0' };
	char * ret = NULL;

	/* Disabling echo */
	if(tcgetattr(fileno(stdin), &oflags))
		return NULL;

	nflags = oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSAFLUSH, &nflags))
		return NULL;

	/* Read the password */
	fprintf(stderr, "%s", prompt);
	ret = fgets(password, sizeof(password), stdin);

	/* Restore echo */
	if (tcsetattr(fileno(stdin), TCSAFLUSH, &oflags))
	{
		my_memset_s(password, 0, sizeof(password));
		return NULL;
	}

	if(ret)
	{
		strtok(password, "\n");
		ret = strdup(password);
		my_memset_s(password, 0, sizeof(password));
	}

	return ret;
}


int runSQLCommand(MYSQL *conn, const char *query)
{
	if (mysql_query(conn, query))
		return 1;
	return 0;
}


int main(int argc, char *argv[]) 
{
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;

	size_t arglen, esclen, fmtlen;

	char *server = "localhost";
	char *user = "root";
	char *database = "bank";
	char *password;
	char *query;
	char *fmtString = "SELECT * FROM users WHERE firstname LIKE '%s'";
	char *param_escaped;
	
	if (argc < 2)
	{
		printf("You should give an entry parameter!\n");
		return -1;
	}
	
	conn = mysql_init(NULL);
	if(!conn)
		return -1;

	password = getpass_r("DB Password: ");
	if(!password)
	{
		mysql_close(conn);
		return -1;
	}

	/* Connect to database */
	if (!mysql_real_connect(conn, server,
			user, password, database, 0, NULL, 0)) {
		my_memset_s(password, 0, strlen(password));
		free(password);
		mysql_close(conn);
		return -1;
	}

	my_memset_s(password, 0, strlen(password));
	free(password);

	/* send SQL query */

	// allocate memory to sanitize the query
	arglen = strlen(argv[1]);
	if(arglen > (SIZE_MAX / sizeof *param_escaped - 1) / 2)
	{
		// the operation would cause an integer overflow
		mysql_close(conn);
		return -1;
	}
	param_escaped = malloc((2 * arglen + 1) * sizeof *param_escaped);
	if(param_escaped == NULL)
	{
		mysql_close(conn);
		return -1;
	}

	// sanitize the query string
	esclen = mysql_real_escape_string(conn, param_escaped, argv[1], arglen);	/* FIX */

	// allocate memory for the query
	fmtlen = strlen(fmtString);
	if(esclen > SIZE_MAX / sizeof *query - fmtlen)
	{
		// the operation would cause an integer overflow
		free(param_escaped);
		mysql_close(conn);
		return -1;
	}
	query = malloc((esclen + fmtlen + 1) * sizeof *query);
	if(query == NULL)
	{
		free(param_escaped);
		mysql_close(conn);
		return -1;
	}

	sprintf(query,fmtString,param_escaped);

	if (runSQLCommand(conn, (const char *)query))
	{
		free(param_escaped);
		free(query);
		mysql_close(conn);
		return -1;
	}
	
	res = mysql_use_result(conn);
	
	/* output fields 1 and 2 of each row */
	while ((row = mysql_fetch_row(res)) != NULL)
		printf("%s %s\n", row[1], row[2]);
	
	/* Release memory used to store results and close connection */
	free(param_escaped);
	free(query);
	mysql_free_result(res);
	mysql_close(conn);
	return 0;
}
