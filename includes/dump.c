#ifndef B_DUMP
#define B_DUMP 1

#include <stdio.h>

int b_dump(unsigned char *buf, unsigned char mode, unsigned long group, unsigned long len);

int b_dump(unsigned char *buf, unsigned char mode, unsigned long group, unsigned long len)
{
	unsigned long x = 0, y;

	switch(mode)
	{
		case 'X':
			while(x < len)
			{
				for(y ^= y; y < group && x < len; y++)
				{
					printf("%02X", *(buf + x));
					x++;
				}
				if(x < len)
					printf(" ");
			}
			break;
		case 'x':
			while(x < len)
			{
				for(y ^= y; y < group && x < len; y++)
				{
					printf("%02x", *(buf + x));
					x++;
				}
				if(x < len)
					printf(" ");
			}
			break;
		case 'd':
			break;
		case 'C':
			while(x < len)
			{
				printf("\"");
				for(y ^= y; y < group && x < len; y++)
				{
					printf("%c", *(buf + x));
					x++;
				}
				if(x < len);
					printf("\" ");
			}
			break;
		case 'c':
			while(x < len)
			{
				for(y ^= y; y < group && x < len; y++)
				{
					printf("%c", *(buf + x));
					x++;
				}
				if(x < len)
					printf(" ");
			}
			break;
		default:
			printf("Invalid b_dump mode.\n");
			break;
	}
}

#endif
