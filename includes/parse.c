#ifndef B_PARSE
#define B_PARSE 1

#include <stdio.h>
#include <string.h>
#include <malloc.h>

struct char_piece
{
	char *item;
	struct char_piece *next;
};

unsigned long ReadNum(char *num);
unsigned long isNum(char *num);
unsigned long SplitByChar(char *text, char delim, char ***list);
unsigned long QSplitByChar(char *text, char delim, char ***list);
unsigned long SplitByLine(char *text, char ***list);
unsigned long aEQ(char *text, char *text2);
unsigned long aEQl(char *text, char *text2, unsigned long len);
char *aEQb(char *text, char *buf, unsigned long buflen);
char *aEQbl(char *text, unsigned long len, char *buf, unsigned long buflen);
unsigned long freeList(char ***list, unsigned long num);
unsigned long inList(char *text, char **list, unsigned long num);
unsigned long inListb(char *text, char **list, unsigned long num);
struct char_piece* mkCharPiece(char *item);
unsigned long CharChainToList(struct char_piece **char_chain, char ***list);
struct char_piece *LastCharPiece(struct char_piece *char_chain);
void FreeCharChain(struct char_piece *char_chain);

unsigned long ReadNum(char *num)
{
	unsigned long x, mul = 1, n = 0;
	
	if(!isNum(num))
		return 0;
	
	if(num[0] == 0)
		return 0;
	
	if(num[1] != 0)
		for(x = 1; num[x] != 0; x++)
			mul *= 10;
	
	for(x ^= x; num[x] != 0; x++)
	{
		n += mul * (num[x] - '0');
		mul /= 10;
	}
	
	return n;
}

unsigned long isNum(char *num)
{
	unsigned long x;
	
	if(num == NULL)
		return 0;
	
	for(x ^= x; num[x] != 0; x++)
		if(num[x] < '0' || num[x] > '9')
			return 0;
	
	return 1;
}

unsigned long SplitByChar(char *text, char delim, char ***list)
{
	unsigned long x, y, pos = 0, lines = 0;
	
	if(text == NULL || list == NULL)
		return 0;
	
	for(x ^= x; text[x] != 0; x++)
		if(text[x] == delim)
			lines++;
	
	if(text[x - 1] != delim)
		lines++;
	
	*list = (char**)malloc(lines * sizeof(char**));
	
	for(y ^= y; y < lines; y++)
	{
		for(x ^= x; text[pos + x] != delim && text[pos + x] != 0; x++);
		(*list)[y] = (char*)malloc(x + 1);
		for(x ^= x; text[pos + x] != delim && text[pos + x] != 0; x++)
			*((*list)[y] + x) = text[pos + x];
		*((*list)[y] + x) = 0;
		pos += ++x;
	}
	
	return lines;
}

unsigned long QSplitByChar(char *text, char delim, char ***list)
{
	unsigned long x, y, pos = 0, lines = 0;
	unsigned char quote = 0;
	
	if(text == NULL || list == NULL)
		return 0;
	
	for(x ^= x; text[x] != 0; x++)
	{
		if(text[x] == '\"' || text[x] == '\'')
		{
			if(quote == text[x])
				quote = 0;
			else
				quote = text[x];
		}
		if(text[x] == delim && quote == 0)
			lines++;
	}
	
	if(text[x - 1] != delim)
		lines++;
	
	*list = (char**)malloc(lines * sizeof(char**));
	
	for(y ^= y; y < lines; y++)
	{
		for(x ^= x; (text[pos + x] != delim || quote != 0) && text[pos + x] != 0; x++)
		{
			if(text[pos + x] == '\"' || text[pos + x] == '\'')
			{
				if(quote == text[pos + x])
					quote = 0;
				else
					quote = text[pos + x];
			}
		}
		(*list)[y] = (char*)malloc(x + 1);
		for(x ^= x; (text[pos + x] != delim || quote != 0) && text[pos + x] != 0; x++)
		{
			if(text[pos + x] == '\"' || text[pos + x] == '\'')
			{
				if(quote == text[pos + x])
					quote = 0;
				else
					quote = text[pos + x];
			}
			*((*list)[y] + x) = text[pos + x];
		}
		*((*list)[y] + x) = 0;
		pos += ++x;
	}
	
	return lines;
}

unsigned long SplitByLine(char *text, char ***list)
{
	unsigned long x, y, pos = 0, lines = 0;
	
	if(text == NULL)
		return 0;
	
	for(x ^= x; text[x] != 0; x++)
	{
		if(text[x] == '\n')
			lines++;
	}
	
	if(text[x - 1] != '\n')
		lines++;
	
	*list = (char**)malloc(lines * sizeof(char**));
	
	for(y ^= y; y < lines; y++)
	{
		for(x ^= x; text[pos + x] != '\n' && text[pos + x] != 0; x++);
		if(text[pos + x - 1] == '\r')
			x--;
		(*list)[y] = (char*)malloc(x + 1);
		for(x ^= x; !(text[pos + x] == '\r' && text[pos + x + 1] == '\n') && text[pos + x] != '\n' && text[pos + x] != 0; x++)
			*((*list)[y] + x) = text[pos + x];
		*((*list)[y] + x) = 0;
		pos += x;
		if(text[pos++] == '\r')
			pos++;
	}
	
	return lines;
}

unsigned long aEQ(char *text, char *text2)
{
	unsigned long x, y;
	char tmp, tmp2;
	
	if(text == NULL || text2 == NULL)
		return 0xFFFFFFFF;

	for(x ^= x; text[x] != 0; x++);
	for(y ^= y; text2[y] != 0; y++);
	if(x != y)
		return 0xFFFFFFFE;
		
	for(x ^= x; text[x] != 0 && text2[x] !=  0; x++)
	{
		tmp = text[x];
		tmp2 = text2[x];
		
		if(tmp <= 'Z' && tmp >= 'A')
			tmp |= 0x20;
		if(tmp2 <= 'Z' && tmp2 >='A')
			tmp2 |= 0x20;
		if(tmp != tmp2)
			break;
	}
	
	if(x != y)
	{
		if(x == 0)
			return 0xFFFFFFFD;
		return x;
	}
	
	return 0;
}

unsigned long aEQl(char *text, char *text2, unsigned long len)
{
	unsigned long x;
	char tmp, tmp2;
	
	if(text == NULL || text2 == NULL || len == 0)
		return 0xFFFFFFFF;
	
	for(x ^= x; text[x] != 0 && text2[x] !=  0 && x < len; x++)
	{
		tmp = text[x];
		tmp2 = text2[x];
		
		if(tmp <= 'Z' && tmp >= 'A')
			tmp |= 0x20;
		if(tmp2 <= 'Z' && tmp2 >='A')
			tmp2 |= 0x20;
		if(tmp != tmp2)
			break;
	}
	
	if(x != len)
	{
		if(x == 0)
			return 0xFFFFFFFD;
		return x;
	}
	
	return 0;
}

char *aEQb(char *text, char *buf, unsigned long buflen)
{
	unsigned long x, y, len;
	char tmp, tmp2;
	
	if(text == NULL || buf == NULL || buflen == 0)
		return NULL;
	
	for(len ^= len; text[len] != 0; len++);
	if(len == 0 || len > buflen)
		return NULL;
	
	for(x ^= x; x < (buflen - (len - 1)); x++)
	{
		for(y ^= y; y < len && x + y < buflen; y++)
		{
			tmp = text[y];
			tmp2 = buf[x + y];
		
			if(tmp <= 'Z' && tmp >= 'A')
				tmp |= 0x20;
			if(tmp2 <= 'Z' && tmp2 >='A')
				tmp2 |= 0x20;
			if(tmp != tmp2)
				break;
		}
		
		if(y == len)
			return (buf + x);
	}
	
	return NULL;
}

char *aEQbl(char * text, unsigned long len, char *buf, unsigned long buflen)
{
	unsigned long x, y;
	char tmp, tmp2;
	
	if(text == NULL || buf == NULL || buflen == 0 || len == 0 || len > buflen)
		return NULL;
	
	for(x ^= x; x < (buflen - (len - 1)); x++)
	{
		for(y ^= y; y < len && x + y < buflen; y++)
		{
			tmp = text[y];
			tmp2 = buf[x + y];
		
			if(tmp <= 'Z' && tmp >= 'A')
				tmp |= 0x20;
			if(tmp2 <= 'Z' && tmp2 >='A')
				tmp2 |= 0x20;
			if(tmp != tmp2)
				break;
		}
		
		if(y != len)
			return (buf + x);
	}
	
	return NULL;
}

unsigned long freeList(char ***list, unsigned long num)
{
	unsigned long x;
	
	if(list == NULL || num == 0)
		return 0xFFFFFFFF;
	
	for(x ^= x; x < num; x++)
		free((*list)[x]);
	free(*list);
	*list = NULL;
	
	return 0;
}

unsigned long inList(char *text, char **list, unsigned long num)
{
	unsigned long x;
	
	if(text == NULL || list == NULL || num == 0)
		return 0;
	
	for(x ^= x; x < num; x++)
		if(aEQ(text, list[x]) == 0)
			return 1;
	return 0;
}

unsigned long inListb(char *text, char **list, unsigned long num)
{
	unsigned long x;
	
	if(text == NULL || list == NULL || num == 0)
		return 0;
	
	for(x ^= x; x < num; x++)
		if(aEQb(list[x], text, strlen(text)))
			return 1;
	return 0;
}

struct char_piece* mkCharPiece(char *item)
{
	struct char_piece *c_piece = NULL;
	
	c_piece = malloc(sizeof(struct char_piece));
	c_piece->item = item;
	c_piece->next = NULL;
	
	return c_piece;
}

unsigned long CharChainToList(struct char_piece **char_chain, char ***list)
{
	unsigned long x;
	struct char_piece *c_piece = *char_chain;
	
	for(x ^= x; c_piece != NULL; x++)
		c_piece = c_piece->next;
	
	*list = malloc(sizeof(char*) * x);
	c_piece = *char_chain;
	for(x ^= x; c_piece != NULL; x++)
	{
		(*list)[x] = c_piece->item;
		c_piece = c_piece->next;
		free(*char_chain);
		*char_chain = c_piece;
	}
	
	return x;
}

struct char_piece *LastCharPiece(struct char_piece *char_chain)
{
	while(char_chain->next != NULL)
		char_chain = char_chain->next;
	
	return char_chain;
}

void FreeCharChain(struct char_piece *char_chain)
{
	struct char_piece *c_piece = NULL, *tpiece = NULL;
	
	c_piece = char_chain;
	while(c_piece != NULL)
	{
		tpiece = c_piece;
		c_piece = c_piece->next;
		if(tpiece->item)
			free(tpiece->item);
		free(tpiece);
	}
}

#endif
