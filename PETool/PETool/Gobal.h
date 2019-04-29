#pragma once

/*
Save_buffer ����buffer���ļ�
LPSTR path----------����·��
LPVOID buffer-------bufferָ��
long size_exe-------�����ļ���С
*/
void Save_buffer(LPSTR path,LPVOID buffer, long size_exe);

/*
Read_file_buffer ��ȡӲ�����ļ���buffer
IN LPSTR path          ��ȡ�ļ�·��
OUT LPVOID *buffer     buffer��ָ��
*/
DWORD Read_file_buffer(IN LPSTR path, OUT LPVOID *buffer);

/*
Copyfilebuffertoimagebuffer      �ļ���ʽת��Ϊ�ڴ��ʽ
IN LPVOID pfile_buffer            �ļ���ʽ��buffer
OUT LPVOID *pimage_buffer         �ڴ��ʽ��buffer
*/
DWORD Copyfilebuffertoimagebuffer(IN LPVOID pfile_buffer, OUT LPVOID *pimage_buffer);

/*
CopyImagebuffertofilebuffer ���ڴ��ʽת��Ϊ�ļ���ʽ
IN LPVOID pimage_buffer     �ڴ��ʽ��buffer
OUT LPVOID *pnew_buffer     �ļ���ʽ��buffer

*/
DWORD CopyImagebuffertofilebuffer(IN LPVOID pimage_buffer, OUT LPVOID *pnew_buffer);
/*
TestAddCodeIncodeSe���п��е�����Ӵ���
IN LPSTR from_path ----��ȡ�ļ�·��
OUT LPSTR to_path---����·��

*/
void  TestAddCodeIncodeSe(IN LPSTR from_path, OUT LPSTR to_path);

/*
TestAddSe��ӽ�
IN LPSTR from_path ----��ȡ�ļ�·��
OUT LPSTR to_path---����·��

����ֵ-������ε��ļ�ƫ��
*/
DWORD  TestAddSe(IN LPSTR from_path, OUT LPSTR to_path);

/*
ShowIED ��ʾ��������Ϣ
IN LPVOID pfile_buffer ----file�ļ�ָ��
*/
void  ShowIED(IN LPVOID pfile_buffer);

/*
RVA_to_FOA ���ڴ���ƫ��ת��Ϊ�ļ���ƫ��
IN DWORD RVA----------------------------�ڴ���ƫ��
IN PIMAGE_FILE_HEADER pPEHeader---------image_file_headerָ��

����FOA----------------------------------�ļ���ƫ��
*/
DWORD RVA_to_FOA(IN DWORD RVA, IN PIMAGE_FILE_HEADER pPEHeader);

/*
GetFunctionAddrByName ͨ�����������ҵ�������ַ
IN LPSTR FunctionName-------------------������
IN LPVOID pfile_buffer------------------�ļ�ָ��

���غ���RVA
*/
DWORD GetFunctionAddrByName(IN LPSTR FunctionName, IN LPVOID pfile_buffer);

/*
GetFunctionAddrByOrdinals ͨ����������ҵ�������ַ
IN LPSTR NumberOrdinals-------------------�������
IN LPVOID pfile_buffer------------------�ļ�ָ��

���غ���RVA
*/
DWORD GetFunctionAddrByOrdinals(IN DWORD NumberOrdinals, IN LPVOID pfile_buffer);

/*
TestShowReLocation ��ʾ�ض�λ����Ϣ
IN LPVOID pfile_buffer ---file_bufferλ��
*/
void TestShowReLocation(IN LPVOID pfile_buffer);

/*
MoveIEDtoNewSg �������ת�Ƶ��µĽ���
IN LPSTR from_path ----��ȡ�ļ�·��
OUT LPSTR to_path---����·��
*/
void MoveIEDtoNewSg(IN LPSTR from_path, OUT LPSTR to_path);