// PETool.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "Gobal.h"

int main()
{


	/*
	//复制输出表到新的节
	char path[] = "testdll.dll";
	char path2[] = "New_testdll.dll";
	MoveIEDtoNewSg(path,path2 );
	

	//测试新的节是否正确
	char path[] = "New_testdll.dll";
	LPVOID file_buffer;
	Read_file_buffer(path, &file_buffer);
	if (file_buffer != NULL)ShowIED(file_buffer);
	*/

	/*
	//显示重定位表

	char path[] = "testdll.dll";
	LPVOID file_buffer;
	
	Read_file_buffer(path, &file_buffer);
	if (file_buffer != NULL)TestShowReLocation(file_buffer);
	*/


	/*输出表

	//显示导出表信息
	char path[] = "testdll.dll";
	LPVOID file_buffer;
	Read_file_buffer(path, &file_buffer);
	if (file_buffer != NULL)ShowIED(file_buffer);


	//根据函数名找出函数的RVA
	char functionname[] = "Deinitialize";
	if (file_buffer != NULL)GetFunctionAddrByName(functionname,file_buffer);

	//根据导出序号找出函数的RVA
	DWORD NumerOrdinals=2;
	if (file_buffer != NULL)GetFunctionAddrByOrdinals(NumerOrdinals, file_buffer);

	if (file_buffer != NULL) {
		free(file_buffer);
	}
	*/

	/*
	//添加空白区段
	char path[] = "1.exe";
	char  path2[] = "add_se_.exe";
	DWORD addse_address = 0;
	addse_address=TestAddSe(path,path2);
	*/

	/*添加代码
	char   path[] = "1.exe";
	char path2[] = "3.exe";
	TestAddCodeIncodeSe(path, path2);
     */

	/*test1
	LPVOID file_buffer,image_buffer,new_buffer=NULL;
	DWORD file_size,image_size,new_size;
	
	char   path[]="1.exe";
	char path2[] = "2.exe";

	cout << "-------------读取文件-------------------" << endl;
	file_size=Read_file_buffer(path,&file_buffer);

	cout <<"--------------复制到image_buffer---------"<<endl;
	if (file_buffer != NULL)image_size = Copyfilebuffertoimagebuffer(file_buffer, &image_buffer);
	

	cout << "--------------复制到new_buffer---------" << endl;
	if (image_buffer != NULL)new_size = CopyImagebuffertofilebuffer(image_buffer, &new_buffer);
	  
	if (new_buffer != NULL)Save_buffer(path2,new_buffer,new_size);

	//释放空间
	if (file_buffer != NULL) {
		free(file_buffer);
	}
	if (image_buffer!=NULL)
		{
			free(image_buffer);
		}

	if (new_buffer != NULL) {
		free(new_buffer);
	}
	*/
    return 0;
}

