/*
 * @lc app=leetcode.cn id=4 lang=c
 *
 * [4] 寻找两个正序数组的中位数
 */

// @lc code=start


double findMedianSortedArrays(int* nums1, int nums1Size, int* nums2, int nums2Size)
{

    float tmp1 = 0, tmp2 = 0;
    int p_1 = 0, p_2 = 0, p = 0, q = 0, i = 0;
    p = (nums1Size + nums2Size) / 2 ;
	q = (nums1Size + nums2Size) % 2;
	
    for(i=0; i<=p; i++)
    {
		if((p_1 >= nums1Size) && (p_2 >= nums2Size))
		{
			//printf("p_1:%f\n", p_1);
			//printf("p_2:%f\n", p_2);
			break;
		}
        tmp1 = tmp2;
		if(p_1 >= nums1Size)
		{
			tmp2 = nums2[p_2];
            p_2 ++;
		}
		else if (p_2 >= nums2Size)
		{
			tmp2 = nums1[p_1];
			p_1 ++;
		}
		
		else
		{
			if(nums1[p_1] < nums2[p_2])
			{
				tmp2 = nums1[p_1];
				p_1 ++;
			}
			else if(nums1[p_1] > nums2[p_2])
			{
				tmp2 = nums2[p_2];
				p_2 ++;
			}
			else
			{
				tmp2 = nums1[p_1];
				p_1 ++;
				//p_2 ++;
			}
		}
        printf("tmp1:%f\n", tmp1);
		printf("tmp2:%f\n", tmp2);
		printf("****************");
    }
	
    if(q != 0)
    {
		//printf("ret:%f\n", tmp2);
		return tmp2;
    }
    else
    {
        return (tmp1 + tmp2) /2;
    }
}


void main(void)
{
	int nums1[] = {0,0,0,0,0};
	int nums2[] = {-1,0,0,0,0,0,1};
	
	double ret = 0;
	
	ret = findMedianSortedArrays(nums1, 5, nums2, 7);
	
	printf("ret:%f\n", ret);
}




