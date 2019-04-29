#include "stdafx.h"
#include "Gobal.h"


//massagebox��ϵͳ��λ��
#define MESSAGEBOXADDR 0x74077e60
//��ӵĴ���
BYTE Add_code[] = {
	0xC7,0x44,0x24,0x0C,0x00,0x00,0x00,0x00,       //8
	0xC7,0x44,0x24,0x08,0x00,0x00,0x00,0x00,        //8
	0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,         //8
	0xC7,0x04,0x24,0x00,0x00,0x00,0x00,             //7
	0xe8,0x00,0x00,0x00,0x00,                   //5
	0xe9,0x00,0x00,0x00,0x00,               //5
	0x41,0x65,0x67,0x69,0x73,0x00, // Aegis     6
	0xBB,0xB6,0xD3,0xAD,0xBC,0xD3,0xC8,0xEB,0xCE,0xD2,0xC3,0xC7,0x00   //��ӭ��������..  13
	



};
//��ӽ�ͷ����Ϣ
BYTE Add_se[] = {
	0x2E,0x41,0x44,0x44,0x73,0x65,0x00,0x00, //8
	0x4C,0x09,0x00,0x00,
	0x00,0x80,0x00,0x00,
	0x00,0x0A,0x00,0x00, 
	0x00,0x24,0x00,0x00,  
	0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,  
	0x60,0x00,0x30,0x60  //����
};

void Save_buffer(LPSTR path , LPVOID buffer, long size_exe) {
	FILE *fp;
	int result;
	result = fopen_s(&fp,path, "wb");//�����ļ�
	if (result) {
		cout << "���ļ�ʧ��" << endl;
		return;
	}
	result = fwrite(buffer, 1, size_exe, fp);
	if (result != size_exe) {
		cout << "д�����ȱʧ" << endl;
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
	if (err == 0) {						//�ɹ���
		cout << "���ļ��ɹ�\n" << endl;
		result = fseek(fp, 0, SEEK_END);
		if (result)//�����ļ�ָ��ʧ��
		{
			perror("Fseek failed");
			return 0;
		}
		size_exe = ftell(fp);
		result = fseek(fp, 0, SEEK_SET);
		if (result) {					//�����ļ�ָ��ʧ��
			perror("return Fseek failed");
			return 0;

		}


		cout << "�ļ���СΪ:" << size_exe << endl;

		pfilebuffer = malloc(size_exe * sizeof(char));
		if (pfilebuffer == NULL) {  //�������ڴ�ռ�ʧ��
			fputs("Memory error", stderr);
			return 0;
		}

		memset(pfilebuffer, 0, size_exe * sizeof(char)); //��ʼ����
		result2 = fread(pfilebuffer, sizeof(char), size_exe * sizeof(char), fp);
		if (result2 != size_exe) {
			fputs("��ȡ�ļ����ܴ���", stderr);

		}

		cout << "�����ڴ���׵�ַΪ:  " << pfilebuffer << endl;

		*buffer = pfilebuffer;
		pfilebuffer = NULL;

		fclose(fp);
		return  size_exe;   //���ݴ�С
	}
	else {
		cout << "���ļ�ʧ��\n" << endl;
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
		cout<<"���뻺������Ч"<<endl;
		return 0;
	}
	//MZ���
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout<<"������ЧMZ���\n"<<endl;
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE�ļ�
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout<<"������ЧPE�ļ�"<<endl;
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//��׼peͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡpeͷ
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷָ��
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//����ռ�
	pTempImageBuffer = malloc((DWORD)pOptionHeader->SizeOfImage);
	if (pTempImageBuffer == NULL) {
		cout<<"����ռ�ʧ��"<<endl;
		return 0;
	}

	memset(pTempImageBuffer, 0, (DWORD)pOptionHeader->SizeOfImage);

	//����header
	result = memcpy_s(
		pTempImageBuffer, 
		(DWORD)pOptionHeader->SizeOfHeaders, 
		pfile_buffer, 
		(DWORD)pOptionHeader->SizeOfHeaders
	);

	if (result != 0) {
		cout << "����header����" << endl;
		return 0;
	}
	//����segment

	PIMAGE_SECTION_HEADER ptempSectionHeader = pSectionHeader;
	for (int i = 0; i < (WORD)pPEHeader->NumberOfSections; i++, ptempSectionHeader++) {
		result = memcpy_s(
		   (void *)((DWORD)pTempImageBuffer + ptempSectionHeader->VirtualAddress),
		   (DWORD)ptempSectionHeader->SizeOfRawData,
			(void *)((DWORD)pfile_buffer+ ptempSectionHeader->PointerToRawData),
			(DWORD)ptempSectionHeader->SizeOfRawData
		);
		if (result != 0) {
			cout<<"����segment����"<<endl;
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
		cout << "���뻺������Ч" << endl;
		return 0;
	}
	//MZ���
	if (*((PWORD)pimage_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "������ЧMZ���\n" << endl;
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pimage_buffer;
	//PE�ļ�
	if (*((PWORD)((DWORD)pimage_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "������ЧPE�ļ�" << endl;
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pimage_buffer + pDosHeader->e_lfanew);
	//��׼peͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡpeͷ
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷ
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//���һ����ͷ
	pLast_Section = (PIMAGE_SECTION_HEADER)(
		(DWORD)pSectionHeader+
		((pPEHeader->NumberOfSections-1)*IMAGE_SIZEOF_SECTION_HEADER)
	);

	//����ռ�
	pTempNewBuffer = malloc((DWORD)pLast_Section->PointerToRawData+pLast_Section->SizeOfRawData);
	if (pTempNewBuffer == NULL) {
		cout << "����ռ�ʧ��" << endl;
		return 0;
	}

	memset(pTempNewBuffer, 0, (DWORD)pLast_Section->PointerToRawData + pLast_Section->SizeOfRawData);

	//����header
	result = memcpy_s(
		pTempNewBuffer,
		(DWORD)pOptionHeader->SizeOfHeaders,
		pimage_buffer,
		(DWORD)pOptionHeader->SizeOfHeaders
	);

	if (result != 0) {
		cout << "����header����" << endl;
		return 0;
	}
	//����segment

	PIMAGE_SECTION_HEADER ptempSectionHeader = pSectionHeader;
	for (int i = 0; i < (WORD)pPEHeader->NumberOfSections; i++, ptempSectionHeader++) {
		result = memcpy_s(
			(void *)((DWORD)pTempNewBuffer + ptempSectionHeader->PointerToRawData),
			(DWORD)ptempSectionHeader->SizeOfRawData,
			(void *)((DWORD)pimage_buffer + ptempSectionHeader->VirtualAddress),
			(DWORD)ptempSectionHeader->SizeOfRawData
		);
		if (result != 0) {
			cout << "����segment����" << endl;
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

	int i = 0; //������
	int result = 0;//���ؽ��

	file_size = Read_file_buffer(from_path, &file_buffer);
	if (file_buffer == NULL) {
			cout<<"�ļ�------>file_buffer������ʧ��"<<endl;
	}


	cout << "--------------���Ƶ�image_buffer---------" << endl;
	image_size = Copyfilebuffertoimagebuffer(file_buffer, &image_buffer);
	if (file_buffer == NULL) {
		cout << "file_buffer------>image_buffer������ʧ��" << endl;
	}

    //PE�ļ�
	pDosHeader = (PIMAGE_DOS_HEADER)image_buffer;
	//NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)image_buffer + pDosHeader->e_lfanew);
	//��׼peͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡpeͷ
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷ
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	//���Һ��ʵĲ���λ��
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	
	for (i = 0; i < pPEHeader->NumberOfSections; i++, pTempSectionHeader++) {
		if ((pTempSectionHeader->SizeOfRawData) - (pTempSectionHeader->Misc.VirtualSize) > sizeof(Add_code)/sizeof(BYTE))
		{
			isOK = TRUE;
			break;
		}
	
	}
	
	if (isOK)  //����
	{
		cout<<"��"<<i<<"�ڲ�������"<<endl;
		codebegin = (PBYTE)((DWORD)image_buffer + pTempSectionHeader->VirtualAddress + pTempSectionHeader->Misc.VirtualSize);
		result = memcpy_s(
			codebegin,
			sizeof(Add_code) / sizeof(BYTE),
			Add_code,
			sizeof(Add_code) / sizeof(BYTE)
		);
		if (result != 0) {
			cout<<"����Add_code��image_bufferʧ��"<<endl;
			free(file_buffer);
			free(image_buffer);
			return;
		}

		//�޸�E8,�Բ�ͬ�Ĵ���Ҫ�ֶ��޸�
		DWORD callAddr = (
			MESSAGEBOXADDR -
			(pOptionHeader->ImageBase + ((DWORD)(codebegin+36)-(DWORD)image_buffer))
			);
		*(PDWORD)(codebegin + 32) = callAddr;
		//�޸�E9
		DWORD jmpAddr = (
			(pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) -
			(pOptionHeader->ImageBase+((DWORD)(codebegin+41)-(DWORD)image_buffer))
			);
		*(PDWORD)(codebegin + 37) = jmpAddr;
		//�޸�eip;
		pOptionHeader->AddressOfEntryPoint = (DWORD)(codebegin)-(DWORD)image_buffer;

		//�޸�title
		*(LPLONG)(codebegin + 12) = (long)((pOptionHeader->ImageBase) + ((DWORD)(codebegin+41 )- (DWORD)image_buffer));
		//�޸�text
		*(LPLONG)(codebegin + 20) = (long)((pOptionHeader->ImageBase) + ((DWORD)(codebegin+47)- (DWORD)image_buffer));
	}
	else //û�к��ʵ�����
	{
		cout << "�ռ䲻���޷���������" << endl;
		free(file_buffer);
		free(image_buffer);
		return;
	}


	cout << "--------------���Ƶ�new_buffer-----------" << endl;
	new_size = CopyImagebuffertofilebuffer(image_buffer, &new_buffer);

	Save_buffer(to_path, new_buffer, new_size);

	//�ͷſռ�
	
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

	
	int result = 0;//���ؽ��

	file_size = Read_file_buffer(from_path,&file_buffer);
	



	if (file_buffer == NULL) {
		cout << "���뻺������Ч" << endl;
		return 0;
	}
	//MZ���
	if (*((PWORD)file_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "������ЧMZ���\n" << endl;
		return 0;
	}

	//Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)file_buffer;
	//PE�ļ�
	if (*((PWORD)((DWORD)file_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "������ЧPE�ļ�" << endl;
		return 0;
	}
	//NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)file_buffer + pDosHeader->e_lfanew);
	//��׼peͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡpeͷ
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷ
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//���һ����ͷ
	pLastSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader+ (IMAGE_SIZEOF_SECTION_HEADER) *( pPEHeader->NumberOfSections-1));
	//��ӽ�ͷλ��  = ���һ����ͷ��
	pAddSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader+IMAGE_SIZEOF_SECTION_HEADER*pPEHeader->NumberOfSections);

	//�������,ȷ���������ڵĴ�С
	if (
		(pOptionHeader->SizeOfHeaders - ((DWORD)pAddSectionHeader - (DWORD)file_buffer))
	< 2 * IMAGE_SIZEOF_SECTION_HEADER
		) {

		cout<<"��ͷ�ռ䲻��"<<endl;
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
		cout<<"�������ʧ�ܣ�������"<<endl;
		free(file_buffer);
		return 0;
	}

	//�޸�����

	//�޸Ľ���Ŀ
	pPEHeader->NumberOfSections += 1;
	//�޸��ļ�ƫ��
	pAddSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	//�޸��ڴ�ƫ��
	
	pAddSectionHeader->VirtualAddress = pOptionHeader->SizeOfImage;

	//�޸�sizeofimage  (����Ľ�Ϊһ��sectionaliginment��С)
	pOptionHeader->SizeOfImage = (DWORD)pAddSectionHeader->VirtualAddress + (DWORD)pOptionHeader->SectionAlignment;

	//�����ռ�
	new_buffer = malloc(file_size + (DWORD)pAddSectionHeader->SizeOfRawData);
	memset(new_buffer,0, file_size + (DWORD)pAddSectionHeader->SizeOfRawData);
	if (new_buffer == NULL) {
		cout <<"�����¿ռ�ʧ��"<< endl;
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
		cout << "�������ݵ��¿ռ�ʧ��" << endl;
		free(file_buffer);
		return 0;
	}
	
	Save_buffer(to_path,new_buffer, file_size + (DWORD)pAddSectionHeader->SizeOfRawData);



	//�ͷſռ�
	free(file_buffer);
    free(new_buffer);
	return file_size;
}


DWORD RVA_to_FOA(IN DWORD RVA, IN PIMAGE_FILE_HEADER pPEHeader) {

	//��ѡpeͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷָ��
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//�ڽ�ͷλ�ã�RAV��ΪFOA
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
		cout << "���뻺������Ч" << endl;
		return ;
	}
	//MZ���
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "������ЧMZ���\n" << endl;
		return ;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE�ļ�
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "������ЧPE�ļ�" << endl;
		return ;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//��׼peͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡpeͷ
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷָ��
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	

	//������RVA��ַ
	pExportDirectoryRVA = (LPVOID)pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	//��RVAת��ΪFOA
	if (pExportDirectoryRVA != NULL) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVA_to_FOA((DWORD)pExportDirectoryRVA, pPEHeader)+(DWORD)pfile_buffer);
	  
		
		if (pExportDirectory != NULL) {
		LPSTR a = (LPSTR)RVA_to_FOA((DWORD)pExportDirectory->Name, pPEHeader) + (DWORD)pfile_buffer;
		cout << "Name(ָ��õ������ļ����ַ���):---------------" << a<< endl;
		
		cout << "Base(����������ʼ���):----------------------" << pExportDirectory->Base << endl;
		

		cout << "NumberOfFunctions(���е��������ĸ���)--------" << pExportDirectory->NumberOfFunctions << endl;
		
		cout << "NumberOfName(�Ժ������ֵ����ĺ�������)--------" << pExportDirectory->NumberOfNames << endl;
		
		cout << "AddressOfFunctions(����������ַ��RVA)--------" << pExportDirectory->AddressOfFunctions << endl;
		LPDWORD AddressOfFunctions = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfFunctions, pPEHeader)+(DWORD)pfile_buffer);

		cout << "AddressOfNames(�����������Ʊ�RVA)------------" << pExportDirectory->AddressOfNames << endl;
		LPDWORD AddressOfNames = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNames, pPEHeader) + (DWORD)pfile_buffer);

		cout << "AddressOfNameOrdinals(����������ű�RVA)-----" << pExportDirectory->AddressOfNameOrdinals << endl;
		//AddressOfNameOrdinals  ---file��ƫ�� + file_buffer����ַ 
		LPWORD AddressOfNameOrdinals = (LPWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNameOrdinals, pPEHeader) + (DWORD)pfile_buffer);

		//������ַ��
		cout<<"******������ַ��RVA��*******"<<endl;
		for (int i = 0; i < pExportDirectory->NumberOfFunctions;i++) {
			cout <<"������ַ��"<<AddressOfFunctions[i]<< endl;
		}

		//������ַ��
		cout << "\n******�������Ʊ�*******" << endl;
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
			cout << "�������Ƶ�ַ��----" << AddressOfNames[i] << endl;
			//����������
			LPSTR a = (LPSTR)RVA_to_FOA((DWORD)AddressOfNames[i], pPEHeader) + (DWORD)pfile_buffer;
			cout<<"��������----"<<a<<endl;
		}

		//������ű�
		cout << "\n******������ű�*******" << endl;
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
			cout << "������ţ�" << AddressOfNameOrdinals[i] << endl;
		}

		}
		else {

			cout << "������foa����" << endl;
		}

	}
	else
	{
		cout<<"û�е�����"<<endl;
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
		cout << "���뻺������Ч" << endl;
		return 0;
	}
	//MZ���
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "������ЧMZ���\n" << endl;
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE�ļ�
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "������ЧPE�ļ�" << endl;
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//��׼peͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡpeͷ
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷָ��
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//������RVA��ַ
	pExportDirectoryRVA = (LPVOID)pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//��RVAת��ΪFOA
	if (pExportDirectoryRVA != NULL) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVA_to_FOA((DWORD)pExportDirectoryRVA, pPEHeader) + (DWORD)pfile_buffer);


		if (pExportDirectory != NULL) {
	
			LPDWORD AddressOfFunctions = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfFunctions, pPEHeader) + (DWORD)pfile_buffer);

			LPDWORD AddressOfNames = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNames, pPEHeader) + (DWORD)pfile_buffer);
            
			//AddressOfNameOrdinals  ---file��ƫ�� + file_buffer����ַ 
			LPWORD AddressOfNameOrdinals = (LPWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNameOrdinals, pPEHeader) + (DWORD)pfile_buffer);

			
			
			cout << "\n*************" << endl;
			WORD position = 0;
			for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
				//����������
				LPSTR a = (LPSTR)RVA_to_FOA((DWORD)AddressOfNames[i], pPEHeader) + (DWORD)pfile_buffer;
				if (strcmp(a,FunctionName)==0) {
					cout<<FunctionName<<"λ�ں������Ʊ�ĵ�"<<i<<"��"<<endl;
					isExist = TRUE;
					position = i;
					break;
				}
			}
			if (isExist == TRUE) {
			    //������ű��i λ��
				position = (WORD)AddressOfNameOrdinals[position];
				//������ַ��Ĳ���
				
				FuctionRVA = (DWORD)AddressOfFunctions[position];
				//��ʾRVA
				cout << "�˺�����RVAΪ------" << FuctionRVA << endl;
				return FuctionRVA;
			}

			else
			{
				cout<<"�Ҳ����ú�����"<<endl;
				return 0;
			}



		}
		else {

			cout << "������foa����" << endl;
			return 0;
		}

	}
	else
	{
		cout << "û�е�����" << endl;
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
		cout << "���뻺������Ч" << endl;
		return 0;
	}
	//MZ���
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "������ЧMZ���\n" << endl;
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE�ļ�
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "������ЧPE�ļ�" << endl;
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//��׼peͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡpeͷ
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷָ��
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//������RVA��ַ
	pExportDirectoryRVA = (LPVOID)pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//��RVAת��ΪFOA
	if (pExportDirectoryRVA != NULL) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVA_to_FOA((DWORD)pExportDirectoryRVA, pPEHeader) + (DWORD)pfile_buffer);


		if (pExportDirectory != NULL) {

			LPDWORD AddressOfFunctions = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfFunctions, pPEHeader) + (DWORD)pfile_buffer);

			LPDWORD AddressOfNames = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNames, pPEHeader) + (DWORD)pfile_buffer);

			//AddressOfNameOrdinals  ---file��ƫ�� + file_buffer����ַ 
			LPWORD AddressOfNameOrdinals = (LPWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNameOrdinals, pPEHeader) + (DWORD)pfile_buffer);



			cout << "\n*************" << endl;
			
			
			cout << "���������" << NumberOrdinals << endl;
			//������������� - Base �õ��ں����ĵ�ַ���ƫ��

			NumberOrdinals -= pExportDirectory->Base;

			cout<<"λ�ں�����ַ��ĵ�"<<NumberOrdinals<<"��"<<endl;
			FuctionRVA = AddressOfFunctions[NumberOrdinals];

			//��ʾRVA
			cout << "�˺�����RVAΪ------" << FuctionRVA << endl;
			return FuctionRVA;

		}
		else {

			cout << "������foa����" << endl;
			return 0;
		}

	}
	else
	{
		cout << "û�е�����" << endl;
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
		cout << "���뻺������Ч" << endl;
		return ;
	}
	//MZ���
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "������ЧMZ���\n" << endl;
		return ;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE�ļ�
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "������ЧPE�ļ�" << endl;
		return ;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//��׼peͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡpeͷ
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷָ��
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//�õ�pImageBaseReLocationRVA,λ��data_directory�ĵ�����λ��
	pImageBaseReLocationRVA = pOptionHeader->DataDirectory[5].VirtualAddress;
	if (pImageBaseReLocationRVA != 0) {
	//image_base_relocation
	pImageBaseReLocation = (PIMAGE_BASE_RELOCATION)(RVA_to_FOA(pImageBaseReLocationRVA, pPEHeader)+(DWORD)pfile_buffer);

	for (int i = 0;
		pImageBaseReLocation->SizeOfBlock!=0&&pImageBaseReLocation->VirtualAddress!=0;//�ж��ض�λ��Ľ���
		i++
		) 
	{
		cout<<"********************��"<<i<<"��*************************"<<endl;

		//�˿����ض�λ��ַ�ĸ���
		DWORD number_add = (pImageBaseReLocation->SizeOfBlock - 8) / 2;
		cout<<hex<<pImageBaseReLocation->VirtualAddress<<endl;
		cout<<"�˿���"<<hex<<number_add<<"����ַ(hex)"<<endl;
		LPWORD low_add = (LPWORD)((DWORD)pImageBaseReLocation + 8);
		WORD a = 0;
		for (int j = 0; j < number_add; j++,low_add++) {

			a = (WORD)*low_add;
			cout<<"��"<<j<<"��:\t"
				<<"��ַ\t"<<(DWORD)pImageBaseReLocation->VirtualAddress+(DWORD)((WORD)(a<<4)>>4)
				<< "\t����\t" <<(a>>12)
				<<endl;
		}


		pImageBaseReLocation = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBaseReLocation + (DWORD)pImageBaseReLocation->SizeOfBlock);

	}
	}
	return;

}



void MoveIEDtoNewSg(IN LPSTR from_path, OUT LPSTR to_path) {

	
	//��ӽ�
	LPVOID addse_PointerToRawData = 0;    //����ڵ��ļ�ƫ��
	addse_PointerToRawData=(LPVOID)TestAddSe(from_path, to_path);


	//��ȡ����Ľڵ�����

	LPVOID pfile_buffer=NULL; //��file_buffer������ڵ�buffer
	DWORD file_size = 0;
	file_size=Read_file_buffer(to_path,&pfile_buffer);

	addse_PointerToRawData =(LPVOID)((DWORD)addse_PointerToRawData+(DWORD)pfile_buffer); //���ڴ��е�λ��

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pLastSectionHeader = NULL, pSectionHeader=NULL;


	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	LPVOID pExportDirectoryRVA = NULL;



	int result = 0;

	if (pfile_buffer == NULL) {
		cout << "���뻺������Ч" << endl;
		return;
	}
	//MZ���
	if (*((PWORD)pfile_buffer) != IMAGE_DOS_SIGNATURE) {
		cout << "������ЧMZ���\n" << endl;
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pfile_buffer;
	//PE�ļ�
	if (*((PWORD)((DWORD)pfile_buffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		cout << "������ЧPE�ļ�" << endl;
		return;
	}
	//NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pfile_buffer + pDosHeader->e_lfanew);
	//��׼peͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡpeͷ
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//��һ����ͷָ��
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//���һ����ͷָ��
	//���һ����ͷ
	pLastSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + (IMAGE_SIZEOF_SECTION_HEADER) *(pPEHeader->NumberOfSections - 1));

	
	//������
	pExportDirectoryRVA = (LPVOID)pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (pExportDirectoryRVA != NULL) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVA_to_FOA((DWORD)pExportDirectoryRVA,pPEHeader)+(DWORD)(pfile_buffer));

		//����AddressOfFunction
		LPVOID NewAddressOfFunctions = addse_PointerToRawData;//�½���addressoffunctions��λ��
		LPDWORD AddressOfFunctions = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfFunctions,pPEHeader)+(DWORD)pfile_buffer);
		for (int i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
			result = memcpy_s(
					(void *)addse_PointerToRawData,
					sizeof(DWORD),
				    &AddressOfFunctions[i], //��i����Ŀ�ĵ�ַ
					sizeof(DWORD)
			);
			
			if (result == 0)
				addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 4);
			else {
				cout << "����������ַ���½�ʧ��" << endl;
				return;
			}

		}
	
		//����AddressOfNames
		LPVOID NewAddressOfNames = addse_PointerToRawData;  //�½���addressofnames��λ��
		LPDWORD AddressOfNames = (LPDWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNames, pPEHeader) + (DWORD)pfile_buffer);

		//�������Ʊ�

		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
			result = memcpy_s(
				addse_PointerToRawData,
				sizeof(DWORD),
				&AddressOfNames[i], //��i����Ŀ�ĵ�ַ
				sizeof(DWORD)
			);
			if (result == 0)
				addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 4);
			else {
				cout << "�����������Ʊ��½�ʧ��" << endl;
				return;
			}
		}


		//��������
		LPVOID NewNames = addse_PointerToRawData;//�½���Names��λ��
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {

			char *AddressOfNames2 = (char *)(RVA_to_FOA(AddressOfNames[i],pPEHeader)+(DWORD)pfile_buffer);//�������Ƶĵ�ַ
			DWORD len = strlen(AddressOfNames2);
			result = memcpy_s(
				addse_PointerToRawData,
				len,
				AddressOfNames2, //��i������������
				len
			);
			if (result == 0)
			addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + len);
			else {
				cout<<"�����������Ƶ��½�ʧ��"<<endl;
				return;
			}
		}



		//����AddressOfNameOrdinals
		//  ---file��ƫ�� + file_buffer����ַ 

		LPVOID NewNameOrdinals = addse_PointerToRawData;
		LPWORD AddressOfNameOrdinals = (LPWORD)(RVA_to_FOA((DWORD)pExportDirectory->AddressOfNameOrdinals, pPEHeader) + (DWORD)pfile_buffer);

		//������ű�
		for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
			result = memcpy_s(
				addse_PointerToRawData,
				sizeof(WORD),
				&AddressOfNameOrdinals[i], //��i����Ŀ�ĵ�ַ
				sizeof(WORD)
			);
			if(result==0)
			addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 2);
			else {
				cout<<"����������ű��½�ʧ��"<<endl;
				return;
			}
		}

		//���Ƶ�����
		PIMAGE_EXPORT_DIRECTORY NewIED = (PIMAGE_EXPORT_DIRECTORY)addse_PointerToRawData;
		result = memcpy_s(
			addse_PointerToRawData,
			40,                 //�������С
			pExportDirectory, //��i����Ŀ�ĵ�ַ
			40
		);
		if (result == 0)
			addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 2);
		else {
			cout << "�����������½�ʧ��" << endl;
			return;
		}

		addse_PointerToRawData = (LPVOID)((DWORD)addse_PointerToRawData + 40);

		//����addressoffunctions
		NewIED->AddressOfFunctions =
			(DWORD)NewAddressOfFunctions - (DWORD)pfile_buffer - (DWORD)pLastSectionHeader->PointerToRawData
			+ (DWORD)pLastSectionHeader->VirtualAddress;
		//����addressofnames
		NewIED->AddressOfNames=
			(DWORD)NewAddressOfNames - (DWORD)pfile_buffer - (DWORD)pLastSectionHeader->PointerToRawData
			+ (DWORD)pLastSectionHeader->VirtualAddress;
		//����addressofnameordinals
		NewIED->AddressOfNameOrdinals=
			(DWORD)NewNameOrdinals - (DWORD)pfile_buffer - (DWORD)pLastSectionHeader->PointerToRawData
			+ (DWORD)pLastSectionHeader->VirtualAddress;

		//�������ָ���µ������
		pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress=(DWORD)NewIED - (DWORD)pfile_buffer - (DWORD)pLastSectionHeader->PointerToRawData
			+ (DWORD)pLastSectionHeader->VirtualAddress;

		Save_buffer(to_path,pfile_buffer,file_size);

	}
	

}