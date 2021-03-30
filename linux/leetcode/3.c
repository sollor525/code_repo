int lengthOfLongestSubstring(char * s)
{
	int hash_s[256] = {0};	//hash表。key为字符值，value为在字符串中的index
	
    int loop = 0;
    int cursor_head = 0;	//滑动窗的头
	int count = 0, max = 0;

	//遍历字符串，当其在hash表中第一次出现时，写入哈希表。
	//如果已经出现过，那么就移动滑动窗，将滑动窗的头移动到之前
    for(loop = 0; *(s + loop) != '\0'; loop++)
    {
		if(hash_s[*(s + loop)] > cursor_head)	//已加入过hash表。未加入过的应该hash_s[*(s + loop)]为0，加入时填入的是index。
		{
			printf("cursor_head: %d\n", cursor_head);
			printf("loop: %d\n", loop);
			
			max = max > (loop-cursor_head) ? max : (loop-cursor_head);		//计算max。滑动窗的长度和之前的max做比较取较大的
			cursor_head = hash_s[*(s + loop)];   //滑动窗的头移动到这个字符第一次出现的位置的后一个index
			hash_s[*(s + loop)] = loop+1;	
			printf("cursor_head: %d\n", cursor_head);
			printf("max: %d\n", max);
			printf("***************************\n");
		}
		else
		{
			//更新hash表中对应字符的index。加1是为了避免特殊情况，如第一个字符的velue是0，cursor_head初始也为0，后续和第一个字符重复的话会导致上面的判断不成立。
			hash_s[*(s + loop)] = loop+1;		
		}
		
    }
	max = max > (loop-cursor_head) ? max : (loop-cursor_head);		//计算max。滑动窗的长度和之前的max做比较取较大的
    return max;
}


void main(void)
{
	char str_1[] = "aab";
	int ret = 0;
	
	ret = lengthOfLongestSubstring(str_1);
	printf("%s ret = %d\n", str_1, ret);
	printf("#############################################\n");
	char str_2[] = " ";
	ret = lengthOfLongestSubstring(str_2);
	printf("%s ret = %d\n", str_2, ret);
	printf("#############################################\n");
	char str_3[] = "abcabdef";
	ret = lengthOfLongestSubstring(str_3);
	printf("%s ret = %d\n", str_3, ret);
	printf("#############################################\n");
	char str_4[] = "abcabcbb";
	ret = lengthOfLongestSubstring(str_4);
	printf("%s ret = %d\n", str_4, ret);
}