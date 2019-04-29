#include "stdafx.h"
#include "Gobal.h"


//massagebox在系统的位置
#define MESSAGEBOXADDR 0x74077e60
//添加的代码
BYTE Add_code[] = {
	0xC7,0x44,0x24,0x0C,0x00,0x00,0x00,0x00,       //8
	0xC7,0x44,0x24,0x08,0x00,0x00,0x00,0x00,        //8
	0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,         //8
	0xC7,0x04,0x24,0x00,0x00,0x00,0x00,             //7
	0xe8,0x00,0x00,0x00,0x00,                   //5
	0xe9,0x00,0x00,0x00,0x00,               //5
	0x41,0x65,0x67,0x69,0x73,0x00, // Aegis     6
	0xBB,0xB6,0xD3,0xAD,0xBC,0xD3,0xC8,0xEB,0xCE,0xD2,0xC3,0xC7,0x00   //欢迎加入我们..  13
	



};
//添加节头的信息
BYTE Add_se[] = {
	0x2E,0x41,0x44,0x44,0x73,0x65,0x00,0x00, //8
	0x4C,0x09,0x00,0x00,
	0x00,0x80,0x00,0x00,
	0x00,0x0A,0x00,0x00, 
	0x00,0x24,0x00,0x00,  
	0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,  
	0x60,0x00,0x30,0x60  //属性
};

void Save_buffer(LPSTR path , LPVOID buffer, long size_exe) {
	FILE *fp;
	int result;
	result = fopen_s(&fp,path, "wb");//创建文件
	if (result) {
		cout << "打开文件失败" << endl;
		return;
	}
	result = fwrite(buffer, 1, size_exe, fp);
	if (result != size_exe) {
		cout << "写入可能缺失" << endl;
	}
	fclose(fp);
	return;

	
}

DWORD Read_file_buffer(IN LPSTR path,OUT LPVOID *buffer) {
	long size_exe = 0;
	int result, result2;
	FILE *fp;
	errno_t err;

	LPVOID pfilebuffer = NULL;


	err = fopen_s(&fp, path, "rb");
	if (err == 0) {						//成功打开
		cout << "打开文件成功\n" << endl;
		result = fseek(fp, 0, SEEK_END);
		if (result)//设置文件指针失败
		{
			perror("Fseek failed");
			return 0;
		}
		size_exe = ftell(fp);
		result = fseek(fp, 0, SEEK_SET);
		if (result) {					//设置文件指针失败
			perror("return Fseek failed");
			return 0;

		}


		cout << "文件大小为:" << size_exe << endl;

		pfilebuffer = malloc(size_exe * sizeof(char));
		if (pfilebuffer == NULL) {  //创建堆内存空间失败
			fputs("Memory error", stderr);
			return 0;
		}

		memset(pfilebuffer, 0, size_exe * sizeof(char)); //初始化堆
		result2 = fread(pfilebuffer, sizeof(char), size_exe * sizeof(char), fp);
		if (result2 != size_exe) {
			fputs("读取文件可能错误", stderr);

		}

		cout << "拷贝内存的首地址为:  " << pfilebuffer << endl;

		*buffer = pfilebuffer;
		pfilebuffer = NULL;

		fclose(fp);
		return  size_exe;   //传递大小
	}
	else {
		cout << "打开文件失败\n" << endl;
		return 0;
	}

}


DWORD Copyfilebuffertoimagebuffer(IN  LPVOID  pfile_buffer,OUT LPVOID *pimage_buffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pTempImageBuffer = NULL;

	int result = 0;

	if (pfile_buffer == NULL) {
		cout<<"输入缓冲区无效"<<endl;
		return 0;
	}
	//MZ标记
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout<<"不是有效MZ标记\n"<<endl;
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE文件
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout<<"不是有效PE文件"<<endl;
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//标准pe头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选pe头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头指针
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//分配空间
	pTempImageBuffer = malloc((DWORD)pOptionHeader->SizeOfImage);
	if (pTempImageBuffer == NULL) {
		cout<<"分配空间失败"<<endl;
		return 0;
	}

	memset(pTempImageBuffer, 0, (DWORD)pOptionHeader->SizeOfImage);

	//复制header
	result = memcpy_s(
		pTempImageBuffer, 
		(DWORD)pOptionHeader->SizeOfHeaders, 
		pfile_buffer, 
		(DWORD)pOptionHeader->SizeOfHeaders
	);

	if (result != 0) {
		cout << "拷贝header出错" << endl;
		return 0;
	}
	//复制segment

	PIMAGE_SECTION_HEADER ptempSectionHeader = pSectionHeader;
	for (int i = 0; i < (WORD)pPEHeader->NumberOfSections; i++, ptempSectionHeader++) {
		result = memcpy_s(
		   (void *)((DWORD)pTempImageBuffer + ptempSectionHeader->VirtualAddress),
		   (DWORD)ptempSectionHeader->SizeOfRawData,
			(void *)((DWORD)pfile_buffer+ ptempSectionHeader->PointerToRawData),
			(DWORD)ptempSectionHeader->SizeOfRawData
		);
		if (result != 0) {
			cout<<"拷贝segment出错"<<endl;
		}
		
	}
	*pimage_buffer = pTempImageBuffer;
	pTempImageBuffer = NULL;

	return pOptionHeader->SizeOfImage;

}

DWORD CopyImagebuffertofilebuffer(IN LPVOID pimage_buffer, OUT LPVOID *pnew_buffer) {

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL, pLast_Section=NULL;
	LPVOID pTempNewBuffer = NULL;

	int result = 0;

	if (pimage_buffer == NULL) {
		cout << "输入缓冲区无效" << endl;
		return 0;
	}
	//MZ标记
	if (*((PWORD)pimage_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "不是有效MZ标记\n" << endl;
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pimage_buffer;
	//PE文件
	if (*((PWORD)((DWORD)pimage_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "不是有效PE文件" << endl;
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pimage_buffer + pDosHeader->e_lfanew);
	//标准pe头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选pe头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//最后一个节头
	pLast_Section = (PIMAGE_SECTION_HEADER)(
		(DWORD)pSectionHeader+
		((pPEHeader->NumberOfSections-1)*IMAGE_SIZEOF_SECTION_HEADER)
	);

	//分配空间
	pTempNewBuffer = malloc((DWORD)pLast_Section->PointerToRawData+pLast_Section->SizeOfRawData);
	if (pTempNewBuffer == NULL) {
		cout << "分配空间失败" << endl;
		return 0;
	}

	memset(pTempNewBuffer, 0, (DWORD)pLast_Section->PointerToRawData + pLast_Section->SizeOfRawData);

	//复制header
	result = memcpy_s(
		pTempNewBuffer,
		(DWORD)pOptionHeader->SizeOfHeaders,
		pimage_buffer,
		(DWORD)pOptionHeader->SizeOfHeaders
	);

	if (result != 0) {
		cout << "拷贝header出错" << endl;
		return 0;
	}
	//复制segment

	PIMAGE_SECTION_HEADER ptempSectionHeader = pSectionHeader;
	for (int i = 0; i < (WORD)pPEHeader->NumberOfSections; i++, ptempSectionHeader++) {
		result = memcpy_s(
			(void *)((DWORD)pTempNewBuffer + ptempSectionHeader->PointerToRawData),
			(DWORD)ptempSectionHeader->SizeOfRawData,
			(void *)((DWORD)pimage_buffer + ptempSectionHeader->VirtualAddress),
			(DWORD)ptempSectionHeader->SizeOfRawData
		);
		if (result != 0) {
			cout << "拷贝segment出错" << endl;
			return 0;
		}

	}
	*pnew_buffer = pTempNewBuffer;
	pTempNewBuffer = NULL;

	return (DWORD)pLast_Section->PointerToRawData + pLast_Section->SizeOfRawData;

}

void  TestAddCodeIncodeSe(IN LPSTR from_path, OUT LPSTR to_path) {
	LPVOID file_buffer, image_buffer, new_buffer = NULL;
	DWORD file_size, image_size, new_size;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PBYTE codebegin = NULL;
	bool isOK = FALSE;
	DWORD size = 0;

	int i = 0; //计数器
	int result = 0;//返回结果

	file_size = Read_file_buffer(from_path, &file_buffer);
	if (file_buffer == NULL) {
			cout<<"文件------>file_buffer缓冲区失败"<<endl;
	}


	cout << "--------------复制到image_buffer---------" << endl;
	image_size = Copyfilebuffertoimagebuffer(file_buffer, &image_buffer);
	if (file_buffer == NULL) {
		cout << "file_buffer------>image_buffer缓冲区失败" << endl;
	}

    //PE文件
	pDosHeader = (PIMAGE_DOS_HEADER)image_buffer;
	//NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)image_buffer + pDosHeader->e_lfanew);
	//标准pe头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选pe头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	//查找合适的插入位置
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	
	for (i = 0; i < pPEHeader->NumberOfSections; i++, pTempSectionHeader++) {
		if ((pTempSectionHeader->SizeOfRawData) - (pTempSectionHeader->Misc.VirtualSize) > sizeof(Add_code)/sizeof(BYTE))
		{
			isOK = TRUE;
			break;
		}
	
	}
	
	if (isOK)  //插入
	{
		cout<<"第"<<i<<"节插入数据"<<endl;
		codebegin = (PBYTE)((DWORD)image_buffer + pTempSectionHeader->VirtualAddress + pTempSectionHeader->Misc.VirtualSize);
		result = memcpy_s(
			codebegin,
			sizeof(Add_code) / sizeof(BYTE),
			Add_code,
			sizeof(Add_code) / sizeof(BYTE)
		);
		if (result != 0) {
			cout<<"复制Add_code到image_buffer失败"<<endl;
			free(file_buffer);
			free(image_buffer);
			return;
		}

		//修改E8,对不同的代码要手动修改
		DWORD callAddr = (
			MESSAGEBOXADDR -
			(pOptionHeader->ImageBase + ((DWORD)(codebegin+36)-(DWORD)image_buffer))
			);
		*(PDWORD)(codebegin + 32) = callAddr;
		//修改E9
		DWORD jmpAddr = (
			(pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) -
			(pOptionHeader->ImageBase+((DWORD)(codebegin+41)-(DWORD)image_buffer))
			);
		*(PDWORD)(codebegin + 37) = jmpAddr;
		//修改eip;
		pOptionHeader->AddressOfEntryPoint = (DWORD)(codebegin)-(DWORD)image_buffer;

		//修改title
		*(LPLONG)(codebegin + 12) = (long)((pOptionHeader->ImageBase) + ((DWORD)(codebegin+41 )- (DWORD)image_buffer));
		//修改text
		*(LPLONG)(codebegin + 20) = (long)((pOptionHeader->ImageBase) + ((DWORD)(codebegin+47)- (DWORD)image_buffer));
	}
	else //没有合适的区段
	{
		cout << "空间不够无法插入数据" << endl;
		free(file_buffer);
		free(image_buffer);
		return;
	}


	cout << "--------------复制到new_buffer-----------" << endl;
	new_size = CopyImagebuffertofilebuffer(image_buffer, &new_buffer);

	Save_buffer(to_path, new_buffer, new_size);

	//释放空间
	
		free(file_buffer);
		free(image_buffer);
		free(new_buffer);

	return ;


}

DWORD TestAddSe(IN LPSTR from_path, OUT LPSTR to_path) {
	LPVOID file_buffer,new_buffer = NULL;
	DWORD file_size, new_size;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL,pLastSectionHeader=NULL,pAddSectionHeader=NULL;
	PBYTE codebegin = NULL;
	bool isOK = FALSE;

	
	int result = 0;//返回结果

	file_size = Read_file_buffer(from_path,&file_buffer);
	



	if (file_buffer == NULL) {
		cout << "输入缓冲区无效" << endl;
		return 0;
	}
	//MZ标记
	if (*((PWORD)file_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "不是有效MZ标记\n" << endl;
		return 0;
	}

	//Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)file_buffer;
	//PE文件
	if (*((PWORD)((DWORD)file_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "不是有效PE文件" << endl;
		return 0;
	}
	//NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)file_buffer + pDosHeader->e_lfanew);
	//标准pe头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选pe头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//最后一个节头
	pLastSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader+ (IMAGE_SIZEOF_SECTION_HEADER) *( pPEHeader->NumberOfSections-1));
	//添加节头位置  = 最后一个节头后
	pAddSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader+IMAGE_SIZEOF_SECTION_HEADER*pPEHeader->NumberOfSections);

	//添加数据,确认有两个节的大小
	if (
		(pOptionHeader->SizeOfHeaders - ((DWORD)pAddSectionHeader - (DWORD)file_buffer))
	< 2 * IMAGE_SIZEOF_SECTION_HEADER
		) {

		cout<<"节头空间不够"<<endl;
		free(file_buffer);
		return 0;
	}

	result = memcpy_s(
		pAddSectionHeader,
		IMAGE_SIZEOF_SECTION_HEADER,
		Add_se,
		IMAGE_SIZEOF_SECTION_HEADER
	);
	if (result != 0) {
		cout<<"添加数据失败，嘤嘤嘤"<<endl;
		free(file_buffer);
		return 0;
	}

	//修改数据

	//修改节数目
	pPEHeader->NumberOfSections += 1;
	//修改文件偏移
	pAddSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	//修改内存偏移
	
	pAddSectionHeader->VirtualAddress = pOptionHeader->SizeOfImage;

	//修改sizeofimage  (增添的节为一个sectionaliginment大小)
	pOptionHeader->SizeOfImage = (DWORD)pAddSectionHeader->VirtualAddress + (DWORD)pOptionHeader->SectionAlignment;

	//创建空间
	new_buffer = malloc(file_size + (DWORD)pAddSectionHeader->SizeOfRawData);
	memset(new_buffer,0, file_size + (DWORD)pAddSectionHeader->SizeOfRawData);
	if (new_buffer == NULL) {
		cout <<"创建新空间失败"<< endl;
		free(file_buffer);
		return 0;
	}
	result = memcpy_s(
		new_buffer,
		file_size,
		file_buffer,
		file_size
	);
	if (result != 0) {
		cout << "拷贝数据到新空间失败" << endl;
		free(file_buffer);
		return 0;
	}
	
	Save_buffer(to_path,new_buffer, file_size + (DWORD)pAddSectionHeader->SizeOfRawData);



	//释放空间
	free(file_buffer);
    free(new_buffer);
	return file_size;
}


DWORD RVA_to_FOA(IN DWORD RVA, IN PIMAGE_FILE_HEADER pPEHeader) {

	//可选pe头
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头指针
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//在节头位置，RAV即为FOA
	if (RVA < pOptionHeader->SizeOfHeaders) {
		return  RVA;
	}

	for (int i=0; i <= (WORD)pPEHeader->NumberOfSections; i++, pSectionHeader++) {
		DWORD add = (((DWORD)pSectionHeader->SizeOfRawData) > (DWORD)pSectionHeader->Misc.VirtualSize) ? ((DWORD)pSectionHeader->SizeOfRawData) : ((DWORD)pSectionHeader->Misc.VirtualSize);
		if (RVA >= pSectionHeader->VirtualAddress
			&&
			RVA < pSectionHeader->VirtualAddress + add
			)

		{
			return RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		};
	
	}
}



void ShowIED(IN LPVOID pfile_buffer) {
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;


	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	LPVOID pExportDirectoryRVA = NULL;


	int result = 0;

	if (pfile_buffer == NULL) {
		cout << "输入缓冲区无效" << endl;
		return ;
	}
	//MZ标记
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "不是有效MZ标记\n" << endl;
		return ;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE文件
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "不是有效PE文件" << endl;
		return ;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//标准pe头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选pe头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头指针
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	

	//输出表的RVA地址
	pExportDirectoryRVA = (LPVOID)pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	//将RVA转化为FOA
	if (pExportDirectoryRVA != NULL) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVA_to_FOA((DWORD)pExportDirectoryRVA, pPEHeader)+(DWORD)pfile_buffer);
	  
		
		if (pExportDirectory != NULL) {
		LPSTR a = (LPSTR)RVA_to_FOA((DWORD)pExportDirectory->Name, pPEHeader) + (DWORD)pfile_buffer;
		cout << "Name(指向该导出表文件名字符串):---------------" << a<< endl;
		
		cout << "Base(导出函数起始序号):----------------------" << pExportDirectory->Base << endl;
		

		cout << "NumberOfFunctions(所有导出函数的个数)--------" << pExportDirectory->NumberOfFunctions << endl;
		
		cout << "NumberOfName(以函数名字导出的函数个数)--------" << pExportDirectory->NumberOfNames << endl;
		
		cout << "AddressOfFunctions(导出函数地址表RVA)--------" << pExportDirectory->AddressOfFunctions << endl;
		LPDWORD AddressOfFunctions = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfFunctions, pPEHeader)+(DWORD)pfile_buffer);

		cout << "AddressOfNames(导出函数名称表RVA)------------" << pExportDirectory->AddressOfNames << endl;
		LPDWORD AddressOfNames = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNames, pPEHeader) + (DWORD)pfile_buffer);

		cout << "AddressOfNameOrdinals(导出函数序号表RVA)-----" << pExportDirectory->AddressOfNameOrdinals << endl;
		//AddressOfNameOrdinals  ---file中偏移 + file_buffer基地址 
		LPWORD AddressOfNameOrdinals = (LPWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNameOrdinals, pPEHeader) + (DWORD)pfile_buffer);

		//函数地址表
		cout<<"******函数地址表（RVA）*******"<<endl;
		for (int i = 0; i < pExportDirectory->NumberOfFunctions;i++) {
			cout <<"函数地址："<<AddressOfFunctions[i]<< endl;
		}

		//函数地址表
		cout << "\n******函数名称表*******" << endl;
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
			cout << "函数名称地址：----" << AddressOfNames[i] << endl;
			//函数的名称
			LPSTR a = (LPSTR)RVA_to_FOA((DWORD)AddressOfNames[i], pPEHeader) + (DWORD)pfile_buffer;
			cout<<"函数名称----"<<a<<endl;
		}

		//函数序号表
		cout << "\n******函数序号表*******" << endl;
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
			cout << "函数序号：" << AddressOfNameOrdinals[i] << endl;
		}

		}
		else {

			cout << "导出表foa错误" << endl;
		}

	}
	else
	{
		cout<<"没有导出表"<<endl;
	}



}

DWORD GetFunctionAddrByName(IN LPSTR FunctionName, IN LPVOID pfile_buffer) {

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;


	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	LPVOID pExportDirectoryRVA = NULL;

	BOOL isExist = FALSE;
	DWORD FuctionRVA = 0;


	int result = 0;

	if (pfile_buffer == NULL) {
		cout << "输入缓冲区无效" << endl;
		return 0;
	}
	//MZ标记
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "不是有效MZ标记\n" << endl;
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE文件
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "不是有效PE文件" << endl;
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//标准pe头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选pe头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头指针
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//输出表的RVA地址
	pExportDirectoryRVA = (LPVOID)pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//将RVA转化为FOA
	if (pExportDirectoryRVA != NULL) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVA_to_FOA((DWORD)pExportDirectoryRVA, pPEHeader) + (DWORD)pfile_buffer);


		if (pExportDirectory != NULL) {
	
			LPDWORD AddressOfFunctions = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfFunctions, pPEHeader) + (DWORD)pfile_buffer);

			LPDWORD AddressOfNames = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNames, pPEHeader) + (DWORD)pfile_buffer);
            
			//AddressOfNameOrdinals  ---file中偏移 + file_buffer基地址 
			LPWORD AddressOfNameOrdinals = (LPWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNameOrdinals, pPEHeader) + (DWORD)pfile_buffer);

			
			
			cout << "\n*************" << endl;
			WORD position = 0;
			for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
				//函数的名称
				LPSTR a = (LPSTR)RVA_to_FOA((DWORD)AddressOfNames[i], pPEHeader) + (DWORD)pfile_buffer;
				if (strcmp(a,FunctionName)==0) {
					cout<<FunctionName<<"位于函数名称表的第"<<i<<"处"<<endl;
					isExist = TRUE;
					position = i;
					break;
				}
			}
			if (isExist == TRUE) {
			    //函数序号表第i 位，
				position = (WORD)AddressOfNameOrdinals[position];
				//函数地址表的查找
				
				FuctionRVA = (DWORD)AddressOfFunctions[position];
				//显示RVA
				cout << "此函数的RVA为------" << FuctionRVA << endl;
				return FuctionRVA;
			}

			else
			{
				cout<<"找不到该函数名"<<endl;
				return 0;
			}



		}
		else {

			cout << "导出表foa错误" << endl;
			return 0;
		}

	}
	else
	{
		cout << "没有导出表" << endl;
		return 0;
	}


}

DWORD GetFunctionAddrByOrdinals(IN DWORD NumberOrdinals, IN LPVOID pfile_buffer) {



	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;


	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	LPVOID pExportDirectoryRVA = NULL;

	BOOL isExist = FALSE;
	DWORD FuctionRVA = 0;


	int result = 0;

	if (pfile_buffer == NULL) {
		cout << "输入缓冲区无效" << endl;
		return 0;
	}
	//MZ标记
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "不是有效MZ标记\n" << endl;
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE文件
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "不是有效PE文件" << endl;
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//标准pe头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选pe头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头指针
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//输出表的RVA地址
	pExportDirectoryRVA = (LPVOID)pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//将RVA转化为FOA
	if (pExportDirectoryRVA != NULL) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVA_to_FOA((DWORD)pExportDirectoryRVA, pPEHeader) + (DWORD)pfile_buffer);


		if (pExportDirectory != NULL) {

			LPDWORD AddressOfFunctions = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfFunctions, pPEHeader) + (DWORD)pfile_buffer);

			LPDWORD AddressOfNames = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNames, pPEHeader) + (DWORD)pfile_buffer);

			//AddressOfNameOrdinals  ---file中偏移 + file_buffer基地址 
			LPWORD AddressOfNameOrdinals = (LPWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNameOrdinals, pPEHeader) + (DWORD)pfile_buffer);



			cout << "\n*************" << endl;
			
			
			cout << "导出表序号" << NumberOrdinals << endl;
			//函数导出的序号 - Base 得到在函数的地址表的偏移

			NumberOrdinals -= pExportDirectory->Base;

			cout<<"位于函数地址表的第"<<NumberOrdinals<<"处"<<endl;
			FuctionRVA = AddressOfFunctions[NumberOrdinals];

			//显示RVA
			cout << "此函数的RVA为------" << FuctionRVA << endl;
			return FuctionRVA;

		}
		else {

			cout << "导出表foa错误" << endl;
			return 0;
		}

	}
	else
	{
		cout << "没有导出表" << endl;
		return 0;
	}


}

void TestShowReLocation(IN LPVOID pfile_buffer) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;


	DWORD pImageBaseReLocationRVA = NULL;
	PIMAGE_BASE_RELOCATION pImageBaseReLocation = NULL;




	if (pfile_buffer == NULL) {
		cout << "输入缓冲区无效" << endl;
		return ;
	}
	//MZ标记
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "不是有效MZ标记\n" << endl;
		return ;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE文件
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "不是有效PE文件" << endl;
		return ;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//标准pe头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选pe头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头指针
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//得到pImageBaseReLocationRVA,位于data_directory的第六个位置
	pImageBaseReLocationRVA = pOptionHeader->DataDirectory[5].VirtualAddress;
	if (pImageBaseReLocationRVA != 0) {
	//image_base_relocation
	pImageBaseReLocation = (PIMAGE_BASE_RELOCATION)(RVA_to_FOA(pImageBaseReLocationRVA, pPEHeader)+(DWORD)pfile_buffer);

	for (int i = 0;
		pImageBaseReLocation->SizeOfBlock!=0&&pImageBaseReLocation->VirtualAddress!=0;//判断重定位表的结束
		i++
		) 
	{
		cout<<"********************第"<<i<<"块*************************"<<endl;

		//此块中重定位地址的个数
		DWORD number_add = (pImageBaseReLocation->SizeOfBlock - 8) / 2;
		cout<<hex<<pImageBaseReLocation->VirtualAddress<<endl;
		cout<<"此块有"<<hex<<number_add<<"个地址(hex)"<<endl;
		LPWORD low_add = (LPWORD)((DWORD)pImageBaseReLocation + 8);
		WORD a = 0;
		for (int j = 0; j < number_add; j++,low_add++) {

			a = (WORD)*low_add;
			cout<<"第"<<j<<"个:\t"
				<<"地址\t"<<(DWORD)pImageBaseReLocation->VirtualAddress+(DWORD)((WORD)(a<<4)>>4)
				<< "\t属性\t" <<(a>>12)
				<<endl;
		}


		pImageBaseReLocation = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBaseReLocation + (DWORD)pImageBaseReLocation->SizeOfBlock);

	}
	}
	return;

}



void MoveIEDtoNewSg(IN LPSTR from_path, OUT LPSTR to_path) {

	
	//添加节
	LPVOID addse_PointerToRawData = 0;    //新添节的文件偏移
	addse_PointerToRawData=(LPVOID)TestAddSe(from_path, to_path);


	//读取新添的节的内容

	LPVOID pfile_buffer=NULL; //此file_buffer是新添节的buffer
	DWORD file_size = 0;
	file_size=Read_file_buffer(to_path,&pfile_buffer);

	addse_PointerToRawData =(LPVOID)((DWORD)addse_PointerToRawData+(DWORD)pfile_buffer); //在内存中的位置

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pLastSectionHeader = NULL, pSectionHeader=NULL;


	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	LPVOID pExportDirectoryRVA = NULL;



	int result = 0;

	if (pfile_buffer == NULL) {
		cout << "输入缓冲区无效" << endl;
		return;
	}
	//MZ标记
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "不是有效MZ标记\n" << endl;
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE文件
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "不是有效PE文件" << endl;
		return;
	}
	//NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//标准pe头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选pe头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节头指针
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//最后一个节头指针
	//最后一个节头
	pLastSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + (IMAGE_SIZEOF_SECTION_HEADER) *(pPEHeader->NumberOfSections - 1));

	
	//导出表
	pExportDirectoryRVA = (LPVOID)pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (pExportDirectoryRVA != NULL) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVA_to_FOA((DWORD)pExportDirectoryRVA,pPEHeader)+(DWORD)(pfile_buffer));

		//复制AddressOfFunction
		LPVOID NewAddressOfFunctions = addse_PointerToRawData;//新节中addressoffunctions的位置
		LPDWORD AddressOfFunctions = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfFunctions,pPEHeader)+(DWORD)pfile_buffer);
		for (int i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
			result = memcpy_s(
					(void *)addse_PointerToRawData,
					sizeof(DWORD),
				    &AddressOfFunctions[i], //第i个项目的地址
					sizeof(DWORD)
			);
			
			if (result == 0)
				addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 4);
			else {
				cout << "拷贝函数地址表到新节失败" << endl;
				return;
			}

		}
	
		//复制AddressOfNames
		LPVOID NewAddressOfNames = addse_PointerToRawData;  //新节中addressofnames的位置
		LPDWORD AddressOfNames = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNames, pPEHeader) + (DWORD)pfile_buffer);

		//函数名称表

		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
			result = memcpy_s(
				addse_PointerToRawData,
				sizeof(DWORD),
				&AddressOfNames[i], //第i个项目的地址
				sizeof(DWORD)
			);
			if (result == 0)
				addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 4);
			else {
				cout << "拷贝函数名称表到新节失败" << endl;
				return;
			}
		}


		//函数名称
		LPVOID NewNames = addse_PointerToRawData;//新节中Names的位置
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {

			char *AddressOfNames2 = (char *)(RVA_to_FOA(AddressOfNames[i],pPEHeader)+(DWORD)pfile_buffer);//函数名称的地址
			DWORD len = strlen(AddressOfNames2);
			result = memcpy_s(
				addse_PointerToRawData,
				len,
				AddressOfNames2, //第i个函数的名字
				len
			);
			if (result == 0)
			addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + len);
			else {
				cout<<"拷贝函数名称到新节失败"<<endl;
				return;
			}
		}



		//复制AddressOfNameOrdinals
		//  ---file中偏移 + file_buffer基地址 

		LPVOID NewNameOrdinals = addse_PointerToRawData;
		LPWORD AddressOfNameOrdinals = (LPWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNameOrdinals, pPEHeader) + (DWORD)pfile_buffer);

		//函数序号表
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
			result = memcpy_s(
				addse_PointerToRawData,
				sizeof(WORD),
				&AddressOfNameOrdinals[i], //第i个项目的地址
				sizeof(WORD)
			);
			if(result==0)
			addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 2);
			else {
				cout<<"拷贝函数序号表到新节失败"<<endl;
				return;
			}
		}

		//复制导出表
		PIMAGE_EXPORT_DIRECTORY NewIED = (PIMAGE_EXPORT_DIRECTORY)addse_PointerToRawData;
		result = memcpy_s(
			addse_PointerToRawData,
			40,                 //导出表大小
			pExportDirectory, //第i个项目的地址
			40
		);
		if (result == 0)
			addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 2);
		else {
			cout << "拷贝导出表到新节失败" << endl;
			return;
		}

		addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 40);

		//修正addressoffunctions
		NewIED->AddressOfFunctions =
			(DWORD)NewAddressOfFunctions - (DWORD)pfile_buffer - (DWORD)pLastSectionHeader->PointerToRawData
			+ (DWORD)pLastSectionHeader->VirtualAddress;
		//修正addressofnames
		NewIED->AddressOfNames=
			(DWORD)NewAddressOfNames - (DWORD)pfile_buffer - (DWORD)pLastSectionHeader->PointerToRawData
			+ (DWORD)pLastSectionHeader->VirtualAddress;
		//修正addressofnameordinals
		NewIED->AddressOfNameOrdinals=
			(DWORD)NewNameOrdinals - (DWORD)pfile_buffer - (DWORD)pLastSectionHeader->PointerToRawData
			+ (DWORD)pLastSectionHeader->VirtualAddress;

		//将输出表指向新的输出表
		pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress=(DWORD)NewIED - (DWORD)pfile_buffer - (DWORD)pLastSectionHeader->PointerToRawData
			+ (DWORD)pLastSectionHeader->VirtualAddress;

		Save_buffer(to_path,pfile_buffer,file_size);

	}
	

}