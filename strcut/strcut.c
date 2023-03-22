//I use this function on my uC. They get flash data from an ESP8266 over Browser. When content data >1460 a new Packet will transmit. 
//The ESP8266 prints the Socket Info "IPD,SOCKET,PACKETSIZE:DATA. To remove this string i created function above. 
//The strcut function will not clear the complete String. After clearing and moving substring a '\0' will add to end string.
	
#include <inttypes.h>

//Optional, you can use strlen. But for my reasons i create my own
uint16_t strlenx(const char *str)
{
	uint16_t ret = 0;
	while(*str++) { ret++; }
	return ret;
}

//Return 0 = cannot find findstr or endchar
//Return 1 = Substring and Endchar where found
//Parameter str = String to compare, use only static arrays
//Parameter findstr = Find Substring in String
//Parameter endchar = Search from Substring to Enchar in String
uint8_t strcut(char *str, char *findstr, char endchar)
{
	char *strptr = str;
	uint16_t cnt_str = 0;
	uint16_t cnt_find = 0;
	uint16_t find_pos = 0;
	uint16_t str_len = strlenx(findstr) - 1;
	
	while(1)
	{
		if(str[cnt_str++] == findstr[cnt_find]) 
		{ 
			if(cnt_find++ == str_len) 
			{ 
				find_pos = cnt_str - str_len - 1;
				cnt_str++;
				while(str[cnt_str] != endchar)
				{
					if(str[cnt_str++] == 0) { printf("endchar not found..\r\n"); return 0; }
				}
				cnt_str++;
				printf("Found at %i[%c] to %i[%c]\r\nContains: %.*s\r\n\r\n", find_pos, str[find_pos], cnt_str, str[cnt_str], cnt_str - find_pos, &str[find_pos]);
				
				str += find_pos;
				strptr += cnt_str;
	
				while(*strptr)
				{
					*str = *strptr++;
					str += 1;
				}
				*str = '\0';	
				return 1; 
			}
		} else cnt_find = 0;
		if(str[cnt_str] == 0) { printf("String not found..\r\n"); return 0; }
	}	
}

int main(void)
{
  	//Example String that contains 'IPD,n,n:' this String must removed.
  	static char strx[] = ":010010121221321ACACACIPD,0,123::01009800BCD...";
	
	strcut(strx, "IPD,", ':');
	printf("Result: %s\r\n", strx);
	//Result: :010010121221321ACACAC:0100989ABCD...
  
	return 0;
}
