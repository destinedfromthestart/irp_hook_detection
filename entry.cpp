#include "includes.h"
#include "irp/irp.h"

/*
 * this really isnt very special, but is good to detect irp hooks. 
 * feel free to test it with your driver that hooks irp
 * this alone can be bypassed by well hijacking .text, but if you pair it with .text integ checks then its much harder. maybe a todo for future?
 * made by destinedfromthestart of course
*/

NTSTATUS DriverEntry(PDRIVER_OBJECT drvobj, PUNICODE_STRING regpath)
{
	UNREFERENCED_PARAMETER(drvobj);
	/* we arent going to use these anyway since its not for production */
	UNREFERENCED_PARAMETER(regpath);

	DbgPrint("driver entry hit \n"); /* this is for me to make sure the driver is launching since i used dse meme while testing */

	PRIDE::scan_all_drivers(); /* in production you'd ideally want this to return a value to flag or not */

	return STATUS_SUCCESS; /* its always going to return this as long as scan all drivers doesnt bsod since theres no if conditions in here */
}