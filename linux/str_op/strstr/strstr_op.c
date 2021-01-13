/******************************************************************************************************
字符串匹配算法
******************************************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>


//Sunday算法
unsigned int search_sunday(const char *haystack, const char *needle) 
{
    int i = 0;
    
    unsigned int haystack_len    = strlen(haystack);
    unsigned int needle_len      = strlen(needle);
    unsigned int len_subtract = haystack_len - needle_len;
    
    int charStep[256];
    for (i = 0; i < 256; ++i)
        charStep[i] = -1;
    for (i = 0; i < needle_len; ++i)
        charStep[(int)needle[i]] = i;
    
    for (i = 0; i <= len_subtract;)
    {
        int j = 0;
        while (j < needle_len) {
            if (haystack[i] == needle[j]) {
                ++i;
                ++j;
            } else {
                const char* p = haystack + i + needle_len - j;
                if (charStep[(int)*p] == -1) {
                    i = p - haystack + 1;
                } else {
                    i = p - charStep[(int)*p] - haystack;
                }
                break;
            }
        }
        
        if (j == needle_len) {
            return i - needle_len;
        }
    }
    
    return -1;
}


//strstr, linux c 内置函数
unsigned int search_strstr(const char *haystack, const char *needle) 
{
    char *pos_ptr = NULL; 
    int pos = 0;
    
    pos_ptr = strstr(haystack, needle);
    if(pos_ptr != NULL) 
    {
        pos = pos_ptr - haystack;
    }
    else
    {
        return -1;
    }
    return pos;
}


//后缀回溯比较法  （常规BF算法）
//从后面开始进行匹配。当不匹配时，子串整体向右偏移一个单位，再与主串进行比较。
//从而不断进行循环，直到比较到主串最后一个数。不匹配，则返回-1。否则，返回主串开始匹配的位置。
unsigned int search_reverse(const char *haystack,const char *needle)           
{
  int SourceArry = strlen(haystack);                                    //主串的长度
  int SubArry = strlen(needle);                                         //子串的长度
  int pSub  ,pSour =  SubArry;                                          //定义pSub,pSour数值
  if(SubArry==0)
      return -1;
  while(pSour <= SourceArry)                                            //主串是否到了尽头             
  {   
      pSub = SubArry;                                                   //初始化
      while(needle[--pSub]==haystack[--pSour])                          //进行匹配比较
    {
       if(pSour < 0)  return -1;                                        //如果pSour,以子串长度为一组的主串扫描结束
           
       if(pSub == 0)  return  pSour;                                     //为0,匹配成功

    }
    pSour += (SubArry - pSub) +1 ;                                      //进行偏移,pSour值进行恢复与回溯,SubArry - pSub为以前减去的值补回
    
  }

  return -1;
}


inline void build_next(const char* pattern, size_t length, unsigned int* next)
{
	unsigned int i, t;

	i = 1;
	t = 0;
	next[1] = 0;

	while(i < length + 1)
	{
		while(t > 0 && pattern[i - 1] != pattern[t - 1])
		{
			t = next[t];
		}

		++t;
		++i;

		if(pattern[i - 1] == pattern[t - 1])
		{
			next[i] = next[t];
		}
		else
		{
			next[i] = t;
		}
	}

	//pattern末尾的结束符控制，用于寻找目标字符串中的所有匹配结果用
	while(t > 0 && pattern[i - 1] != pattern[t - 1])
	{
		t = next[t];
	}

	++t;
	++i;

	next[i] = t;
}


//查找所有匹配到的情况
unsigned int search_KMP(const char* text, const char* pattern, unsigned int* matches)
{
	unsigned int i, j, n;
    unsigned int text_length =strlen(text);
    unsigned int pattern_length =strlen(pattern);
    unsigned int next[pattern_length + 2];
    
	build_next(pattern, pattern_length, next);

	i = 0;
	j = 1;
	n = 0;

	while(pattern_length + 1 - j <= text_length - i)
	{
		if(text[i] == pattern[j - 1])
		{
			++i;
			++j;

			//发现匹配结果，将匹配子串的位置，加入结果
			if(j == pattern_length + 1)
			{
				matches[n++] = i - pattern_length;
				j = next[j];
			}
		}
		else
		{
			j = next[j];

			if(j == 0)
			{
				++i;
				++j;
			}
		}
	}

	//返回发现的匹配数
	return n;
}


//查找所有匹配到的情况
unsigned int search_KMP_once(const char* text, const char* pattern)
{
	unsigned int i, j;
    unsigned int text_length =strlen(text);
    unsigned int pattern_length =strlen(pattern);
    unsigned int next[pattern_length + 2];
    unsigned int pos = 0;
    
	build_next(pattern, pattern_length, next);

	i = 0;
	j = 1;

	while(pattern_length + 1 - j <= text_length - i)
	{
		if(text[i] == pattern[j - 1])
		{
			++i;
			++j;

			//发现匹配结果
			if(j == pattern_length + 1)
			{
				pos = i - pattern_length;
				return pos;
			}
		}
		else
		{
			j = next[j];

			if(j == 0)
			{
				++i;
				++j;
			}
		}
	}

	return -1;
}


#define UNSIGNED(x) ((unsigned int)x & 0x000000FF)
#define HASHSIZE 10000019
int search_RK(char* s, char* p) {
    int n = strlen(s);
    int m = strlen(p);
    if (m > n || m == 0 || n == 0)
        return -1;
    // sv为S子串的hash结果，pv为字符串p的hash结果，base为x的m-1次方
    unsigned int sv = UNSIGNED(s[0]), pv = UNSIGNED(p[0]), base = 1;
    int i, j;
    // 初始化 sv, pv, base
    for (i = 1; i < m; i++) 
    {
        pv = (pv * 10 + UNSIGNED(p[i])) % HASHSIZE;
        sv = (sv * 10 + UNSIGNED(s[i])) % HASHSIZE;
        base = (base * 10) % HASHSIZE;
    }
    i = m - 1;
    do {
        // 情况一、hash结果相等
        if (sv == pv) {
            for (j = 0; j < m && s[i - m + 1 + j] == p[j]; j++)
                ;
            if (j == m)
                return i - m + 1;
        }
        i++;
        if (i >= n)
            break;
        // O(1)时间更新S子串的hash结果
        sv = (sv + UNSIGNED(s[i - m]) * (HASHSIZE - base)) % HASHSIZE;
        sv = (sv * 10 + UNSIGNED(s[i])) % HASHSIZE;
    } while (i < n);

    return -1;
}
   
   

int main(int argc,char* argv[])
{
    struct timeval tp_start, tp_end;
    float timeuse = 0;
    int i =0;
    unsigned int pos = 0;
    
    char haystack[] = "asdadwwwwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxsollccacwdefvsegfbbbollobbsreeqweqweqasdaollodwwwwwwwwwwwwwsollwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwolloollocasdadwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwsollwwwwwcacwdefvsegfbbbollobbsreeqweqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcasdadwwwwwwwwwwwwwwwollowwwwwcacwdefvsegfbbsollbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbllorbsreeqolloweqwasdadwwwollowwwwwsollwwwwllorwwwwwwwwcacwdefvsolloegfbbbbbsreeqweqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsresollesollqweqweqsxccvvollowwwwwwwwwwwwwzxccacwdeasdadwollowwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwllorwwwwwwwwcasdadwwwwwwwwwwwwwwwwwsollwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccacwdefvsegfbbbsollbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsrlloreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccccvvwwwwwwwwwasdadwwwwwwwwwwwsollwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwllorsollllwwwwwwwwzxccwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsrfvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxsollccwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwsollzxccccvvwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvollowwwwwwwwwwwwzxccwasdadwwwwwwwollowwwwwllorwwwwwwwwcacwdefvsegfbbbbbsreqsxccvvwwwwwwwwwwwwwzllorxccwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccccvvwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvseollogfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbollobbbsrwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccacwdefvsegfbbbbbsreeqweqweqsxccvvollowwwwwwwwwwwwwzxccwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwwcacwdefvsegfbbbbbsreeqllorweqweqsxccvvwwwwwwwwwwwwwzxccccvvwwwwwwwwwasdadwwwwwwwwwwwwwsollwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwsollwwwwwwzxccwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsrsxccvvwwwwwwwwwwwwwzxccwwasdadwwwwwwwwwwwsollrlwwwwwwwwwcacwdefvsegfbbbbbsreeqwasdadwwwwwwwwwwwwwwwwwwwwcacollowdefvsegfbbbbbsreeqweqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccacwdefvollosegfbbbbbsreeqweqweqsxccvvwwwwwwwsollwwwwwzxccwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzolloxolloccwwwcacwdefvsegfbbllorbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccccvvwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreqweqsxccvvwwwwwwwwwwwwwzxccwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccccvvwwwwollowwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwasdadwwwwwwwwwsollwwwwsollwwwwwwwcacwdefvsegfbbbbbsreeqwsolleqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwsollwwwwwwwwzxccwwasdallordwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwllorwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccccvvwollowwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsrwwwwwwwwwwwollocacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwasdadwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcasdadwwwwwwwwwwwwwwwwwwwwcsollacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccacwdefvsegfbbbbbsreeqweqweqsxcasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsrsolleeqweqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccollovvwwwwwwwwwwwwwzxccacwdefvsollsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwsollwwwzxccccvvwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcolloacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsrcvvwwwwwwwwwwwwwzxccwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwllorwwwwwwwwwwzxccwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccccvvwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbsollbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsrwwwwwwwwwwwwwwwwwwwcacwdefvsollsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccccvvllorwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbollobbbsreeqweqweqsxccvvwwwwwwwwwwwwwzolloxccwasdadwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxasdadwwwwwwwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwasdadwwwwwwwwwwwwwwwwwwwwollocacwdefvsegfbbbbbsreeolloqweqweqsxccvvwwwwwwwwwwwwwzxccwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccccvvwwwwwwwwwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsreeqweqweqsxccvvwwwwwwwwwwwwwzxccwasdadwwwwwwwwwwwwwwwwwwwwcacwdefvsegfbbbbbsrwwwwwwwwwwwcacwdefvsegfbbbbbsrsolloreeqweqweqsxccvvwwwwwwwwwwwwwzxccwwwzxcc";
    char needle[] = "sollor";
    
    unsigned int match_len = strlen(haystack);
    unsigned int *match_ptr = NULL;
    
    pos = search_sunday(haystack, needle);
    printf("1. search_sunday get pos:%d\n", pos);
    pos = 0;
    
    pos = search_strstr(haystack, needle);
    printf("2. search_strstr get pos:%d\n", pos);
    pos = 0;
    
    pos = search_reverse(haystack, needle);
    printf("3. search_reverse get pos:%d\n", pos);
    pos = 0;
    
    match_ptr = (unsigned int *)malloc(match_len * sizeof(int));
    pos = search_KMP(haystack, needle, match_ptr);
    printf("4. search_KMP get pos:%d\n", match_ptr[0]);
    free(match_ptr);
    pos = 0;
    
    pos = search_KMP_once(haystack, needle);
    printf("5. search_KMP_once get pos:%d\n", pos);
    pos = 0;
    
    pos = search_RK(haystack, needle);
    printf("6. search_RK get pos:%d\n", pos);
    pos = 0;
    
    int loop =100000;
    /*--------------------------------------------1-------------------------------------------------*/
    gettimeofday(&tp_start, NULL);
    for (i=0; i<loop; i++)
    {
        
        search_sunday(haystack, needle);
        //printf("1. search_sunday get pos:%d\n", pos);
    }
    gettimeofday(&tp_end, NULL);
    
    timeuse = 1000000 * (tp_end.tv_sec - tp_start.tv_sec) + (tp_end.tv_usec - tp_start.tv_usec);
    timeuse /= 1000000;
    printf("1. search_sunday used time:%f seconds\n", timeuse);

    /*--------------------------------------------2-------------------------------------------------*/
    gettimeofday(&tp_start, NULL);
    for (i=0; i<loop; i++)
    {
        search_strstr(haystack, needle);
    }
    gettimeofday(&tp_end, NULL);
    
    timeuse = 1000000 * (tp_end.tv_sec - tp_start.tv_sec) + (tp_end.tv_usec - tp_start.tv_usec);
    timeuse /= 1000000;
    printf("2. search_strstr used time:%f seconds\n", timeuse);

    /*--------------------------------------------3-------------------------------------------------*/
    gettimeofday(&tp_start, NULL);
    for (i=0; i<loop; i++)
    {
        search_reverse(haystack, needle);
    }
    gettimeofday(&tp_end, NULL);
    
    timeuse = 1000000 * (tp_end.tv_sec - tp_start.tv_sec) + (tp_end.tv_usec - tp_start.tv_usec);
    timeuse /= 1000000;
    printf("3. search_reverse used time:%f seconds\n", timeuse);

    /*--------------------------------------------4-------------------------------------------------*/
    match_ptr = (unsigned int *)malloc(match_len * sizeof(int));
    gettimeofday(&tp_start, NULL);
    for (i=0; i<loop; i++)
    {
        pos = search_KMP(haystack, needle, match_ptr);
    }
    gettimeofday(&tp_end, NULL);
    
    timeuse = 1000000 * (tp_end.tv_sec - tp_start.tv_sec) + (tp_end.tv_usec - tp_start.tv_usec);
    timeuse /= 1000000;
    printf("4. search_KMP used time:%f seconds\n", timeuse);
    free(match_ptr);
    
    /*--------------------------------------------5-------------------------------------------------*/
    gettimeofday(&tp_start, NULL);
    for (i=0; i<loop; i++)
    {
        search_KMP_once(haystack, needle);
    }
    gettimeofday(&tp_end, NULL);
    
    timeuse = 1000000 * (tp_end.tv_sec - tp_start.tv_sec) + (tp_end.tv_usec - tp_start.tv_usec);
    timeuse /= 1000000;
    printf("5. search_KMP_once used time:%f seconds\n", timeuse);

    /*--------------------------------------------6-------------------------------------------------*/
    gettimeofday(&tp_start, NULL);
    for (i=0; i<loop; i++)
    {
        search_RK(haystack, needle);
    }
    gettimeofday(&tp_end, NULL);
    
    timeuse = 1000000 * (tp_end.tv_sec - tp_start.tv_sec) + (tp_end.tv_usec - tp_start.tv_usec);
    timeuse /= 1000000;
    printf("6. search_RK used time:%f seconds\n", timeuse);
    
    /*--------------------------------------------7-------------------------------------------------*/

    
    
    
    
    
    
    
    
    
    
    return 0;
}
