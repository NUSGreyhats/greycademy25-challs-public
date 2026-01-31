/* Change this if the SERVER_NAME environment variable does not report
	the true name of your web server. */
#if 1
#define SERVER_NAME cgiServerName
#endif
#if 0
#define SERVER_NAME "www.boutell.dev"
#endif

/* You may need to change this, particularly under Windows;
	it is a reasonable guess as to an acceptable place to
	store a saved environment in order to test that feature. 
	If that feature is not important to you, you needn't
	concern yourself with this. */

#ifdef WIN32
#define SAVED_ENVIRONMENT "c:\\cgicsave.env"
#else
#define SAVED_ENVIRONMENT "/tmp/cgicsave.env"
#endif /* WIN32 */

#include <stdio.h>
#include "cgic.h"
#include <string.h>
#include <stdlib.h>

void Name();
void HandleSubmit();
void ShowForm();
void Coffees();

int cgiMain() {
    char *super_duper_secret_flag = getenv("FLAG");
	cgiHeaderContentType("text/html");
	fprintf(cgiOut, "<HTML><HEAD>\n");
	fprintf(cgiOut, "<TITLE>Coffee Shop</TITLE></HEAD>\n");
	fprintf(cgiOut, "<BODY><H1>Coffee Shop</H1>\n");
    if (cgiFormSubmitClicked("submitbtn") == cgiFormSuccess)
	{
		HandleSubmit();
		fprintf(cgiOut, "<hr>\n");
	}
    ShowForm();
	fprintf(cgiOut, "</BODY></HTML>\n");
	return 0;
}

void HandleSubmit()
{
	Name();
    Coffees();
}

void Name() {
	char name[81];
	cgiFormStringNoNewlines("name", name, 81);
    fprintf(cgiOut, name);
    fprintf(cgiOut, " ");
}

void Coffees() {
	int coffees;
	cgiFormInteger("coffees", &coffees, 0);
	fprintf(cgiOut, "ordered %d coffees.<BR>\n", coffees);
}

void ShowForm()
{
	fprintf(cgiOut, "<!-- 2.0: multipart/form-data is required for file uploads. -->");
	fprintf(cgiOut, "<form method=\"POST\" enctype=\"application/x-www-form-urlencoded\" ");
    // fprintf(cgiOut, "<form method=\"POST\" enctype=\"multipart/form-data\" ");
	fprintf(cgiOut, "	action=\"");
	cgiValueEscape(cgiScriptName);
	fprintf(cgiOut, "\">\n");
	fprintf(cgiOut, "<p>\n");
	fprintf(cgiOut, "Enter your name:\n");
	fprintf(cgiOut, "<p>\n");
	fprintf(cgiOut, "<input type=\"text\" name=\"name\" placeholder=\"name\" value=\"Bob\">\n");
    fprintf(cgiOut, "<p>\n");
    fprintf(cgiOut, "Number of coffees<BR>\n");
	fprintf(cgiOut, "<input type=\"text\" name=\"coffees\" value=\"2\">\n");
	fprintf(cgiOut, "<p>\n");
	fprintf(cgiOut, "<input type=\"submit\" name=\"submitbtn\" value=\"Submit order\">\n");
	fprintf(cgiOut, "</form>\n");
}
