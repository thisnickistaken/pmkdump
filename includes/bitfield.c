#ifndef _BITFIELD_C_RTN
#define _BITFIELD_C_RTN 1
/*#ifndef u32
	#ifdef _LP64
		#define u32 unsigned int
	#else
		#define u32 unsigned long
	#endif
#endif*/
inline unsigned long set(unsigned long *field, unsigned long flag);
inline unsigned long clear(unsigned long *field, unsigned long flag);
inline unsigned long isset(unsigned long field, unsigned long flag);
inline unsigned long unmask(unsigned long field, unsigned long mask);
inline unsigned long mask(unsigned long field, unsigned long mask);

inline unsigned long set(unsigned long *field, unsigned long flag)
{
	*field = *field | flag;
	return *field;
}

inline unsigned long clear(unsigned long *field, unsigned long flag)
{
	*field = *field & ~flag;
	return *field;
}

inline unsigned long isset(unsigned long field, unsigned long flag)
{
	if((field & flag) == flag)
		return 1;
	else
		return 0;
}

inline unsigned long unmask(unsigned long field, unsigned long mask)
{
	return field & mask;
}

inline unsigned long mask(unsigned long field, unsigned long mask)
{
	return field & ~mask;
}
#endif
