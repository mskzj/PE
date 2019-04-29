#pragma once

/*
Save_buffer 保存buffer到文件
LPSTR path----------保存路径
LPVOID buffer-------buffer指针
long size_exe-------保存文件大小
*/
void Save_buffer(LPSTR path,LPVOID buffer, long size_exe);

/*
Read_file_buffer 读取硬盘上文件到buffer
IN LPSTR path          读取文件路径
OUT LPVOID *buffer     buffer的指针
*/
DWORD Read_file_buffer(IN LPSTR path, OUT LPVOID *buffer);

/*
Copyfilebuffertoimagebuffer      文件格式转换为内存格式
IN LPVOID pfile_buffer            文件格式的buffer
OUT LPVOID *pimage_buffer         内存格式的buffer
*/
DWORD Copyfilebuffertoimagebuffer(IN LPVOID pfile_buffer, OUT LPVOID *pimage_buffer);

/*
CopyImagebuffertofilebuffer 将内存格式转换为文件格式
IN LPVOID pimage_buffer     内存格式的buffer
OUT LPVOID *pnew_buffer     文件格式的buffer

*/
DWORD CopyImagebuffertofilebuffer(IN LPVOID pimage_buffer, OUT LPVOID *pnew_buffer);
/*
TestAddCodeIncodeSe在有空闲的区添加代码
IN LPSTR from_path ----读取文件路径
OUT LPSTR to_path---保存路径

*/
void  TestAddCodeIncodeSe(IN LPSTR from_path, OUT LPSTR to_path);

/*
TestAddSe添加节
IN LPSTR from_path ----读取文件路径
OUT LPSTR to_path---保存路径

返回值-添加区段的文件偏移
*/
DWORD  TestAddSe(IN LPSTR from_path, OUT LPSTR to_path);

/*
ShowIED 显示导出表信息
IN LPVOID pfile_buffer ----file文件指针
*/
void  ShowIED(IN LPVOID pfile_buffer);

/*
RVA_to_FOA 将内存中偏移转换为文件中偏移
IN DWORD RVA----------------------------内存中偏移
IN PIMAGE_FILE_HEADER pPEHeader---------image_file_header指针

返回FOA----------------------------------文件中偏移
*/
DWORD RVA_to_FOA(IN DWORD RVA, IN PIMAGE_FILE_HEADER pPEHeader);

/*
GetFunctionAddrByName 通过函数名称找到函数地址
IN LPSTR FunctionName-------------------函数名
IN LPVOID pfile_buffer------------------文件指针

返回函数RVA
*/
DWORD GetFunctionAddrByName(IN LPSTR FunctionName, IN LPVOID pfile_buffer);

/*
GetFunctionAddrByOrdinals 通过导出序号找到函数地址
IN LPSTR NumberOrdinals-------------------导出序号
IN LPVOID pfile_buffer------------------文件指针

返回函数RVA
*/
DWORD GetFunctionAddrByOrdinals(IN DWORD NumberOrdinals, IN LPVOID pfile_buffer);

/*
TestShowReLocation 显示重定位表信息
IN LPVOID pfile_buffer ---file_buffer位置
*/
void TestShowReLocation(IN LPVOID pfile_buffer);

/*
MoveIEDtoNewSg 将输出表转移到新的节中
IN LPSTR from_path ----读取文件路径
OUT LPSTR to_path---保存路径
*/
void MoveIEDtoNewSg(IN LPSTR from_path, OUT LPSTR to_path);