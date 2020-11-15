#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void MyHandleError( char * s );
void MyHandleErrorWithExit( char * s );

#define TOTAL_BYTES_READ    1024
#define OFFSET_BYTES 1024

#include <fstream>
#include <sstream>
#include <iostream>

BOOL CreateRegistryKey( HKEY hKeyParent, LPSTR subkey )
{
    DWORD dwDisposition; //It verify new key is created or open existing key
    HKEY  hKey;
    DWORD Ret;
    Ret =
        RegCreateKeyEx(
            hKeyParent,
            subkey,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            NULL,
            &hKey,
            &dwDisposition );
    if( Ret != ERROR_SUCCESS )
    {
        printf( "Error opening or creating new key\n" );
        return FALSE;
    }
    RegCloseKey( hKey ); //close the key
    return TRUE;
}

BOOL WriteBinaryDataInRegistry( HKEY hKeyParent, LPSTR subkey, LPCSTR valueName, CONST BYTE * lpData, DWORD cbData )
{
    DWORD Ret;
    HKEY hKey;
    //Check if the registry exists
    Ret = RegOpenKeyEx(
        hKeyParent,
        subkey,
        0,
        KEY_WRITE,
        &hKey
    );
    if( Ret == ERROR_SUCCESS )
    {
        if( ERROR_SUCCESS !=
            RegSetValueEx(
                hKey,
                valueName,
                0,
                REG_BINARY,
                lpData,
                cbData ) )
        {
            RegCloseKey( hKey );
            return FALSE;
        }
        RegCloseKey( hKey );
        return TRUE;
    }
    return FALSE;
}

BOOL WriteDataToRegistry( CONST BYTE * lpData, DWORD cbData )
{
    //-------------------------------------------------------------------
    // Declare and initialize variables.
    LPSTR subKey = "Software\\Efremova";
    LPCSTR valueName = "Signature";
    //-------------------------------------------------------------------
    // Create registry key
    if( CreateRegistryKey(
        HKEY_CURRENT_USER,
        subKey ) )
    {
        printf( "Registry key has been created.\n" );
    }
    else
    {
        MyHandleError( "Error during CreateRegistryKey." );
        return FALSE;
    }
    //-------------------------------------------------------------------
    // Create registry key
    if( WriteBinaryDataInRegistry(
        HKEY_CURRENT_USER,
        subKey,
        valueName,
        lpData,
        cbData ) )
    {
        printf( "Data has been wrote to registry.\n" );
    }
    else
    {
        MyHandleError( "Error during writeStringInRegistry." );
        return FALSE;
    }

    return TRUE;
}

std::string GetDataForHash()
{
    std::stringstream ss;

    // number of mouse buttons
    int mouseButtons = GetSystemMetrics( SM_CMOUSEBUTTONS );
    ss << mouseButtons;

    // screen height
    int screenHeight = GetSystemMetrics( SM_CYSCREEN );
    ss << screenHeight;

    // list of disk devices
    DWORD dwSize = MAX_PATH;
    char szLogicalDrives[MAX_PATH] = { 0 };
    DWORD dwResult = GetLogicalDriveStrings( dwSize, szLogicalDrives );

    if( dwResult > 0 && dwResult <= MAX_PATH )
    {
        char * szSingleDrive = szLogicalDrives;
        while( *szSingleDrive )
        {
            ss << szSingleDrive;

            // get the next drive
            szSingleDrive += strlen( szSingleDrive ) + 1;
        }
    }

    // file system of current disk
    char SysNameBuffer[MAX_PATH];

    if( GetVolumeInformation(
        NULL,
        NULL,
        0,
        NULL,
        NULL,
        NULL,
        SysNameBuffer,
        sizeof( SysNameBuffer ) ) )
    {
        ss << SysNameBuffer;
    }

    return ss.str();
}

void Install()
{
    //-------------------------------------------------------------------
    // Copy exe to dest
    const char * src = "BIS_LAB_1.exe";

    std::cout << "Enter dest folder:" << std::endl;
    std::string destFolder;
    std::cin >> destFolder;

    destFolder += src;

    if( CopyFile(
        src, 
        destFolder.c_str(),
        FALSE ) )
    {
        printf("Successfully copied file to dest\n");
    }
    else
    {
        MyHandleErrorWithExit( "Error during CopyFile." );
    }
    //-------------------------------------------------------------------
    // Data for hash
    std::string data = GetDataForHash();

    printf( "Data for hash '%s'\n", data.c_str() );
    //-------------------------------------------------------------------
    // Declare and initialize variables.
    HCRYPTPROV hProv;
    BYTE * pbBuffer = (BYTE *)data.c_str();
    DWORD dwBufferLen = strlen( (char *)pbBuffer ) + 1;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    BYTE * pbSignature;
    DWORD dwSigLen;
    //-------------------------------------------------------------------
    // Acquire a cryptographic provider context handle.
    if( CryptAcquireContext(
        &hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        0 ) )
    {
        printf( "CSP context acquired.\n" );
    }
    else
    {
        MyHandleErrorWithExit( "Error during CryptAcquireContext." );
    }
    //-------------------------------------------------------------------
    // Get the public at signature key. This is the public key
    // that will be used by the receiver of the hash to verify
    // the signature. In situations where the receiver could obtain the
    // sender's public key from a certificate, this step would not be
    // needed.
    if( CryptGetUserKey(
        hProv,
        AT_SIGNATURE,
        &hKey ) )
    {
        printf( "The signature key has been acquired. \n" );
    }
    else
    {
        MyHandleErrorWithExit( "Error during CryptGetUserKey for signkey." );
    }
    //-------------------------------------------------------------------
    // Create the hash object.

    if( CryptCreateHash(
        hProv,
        CALG_MD5,
        0,
        0,
        &hHash ) )
    {
        printf( "Hash object created. \n" );
    }
    else
    {
        MyHandleErrorWithExit( "Error during CryptCreateHash." );
    }
    //-------------------------------------------------------------------
    // Compute the cryptographic hash of the buffer.
    if( CryptHashData(
        hHash,
        pbBuffer,
        dwBufferLen,
        0 ) )
    {
        printf( "The data buffer has been hashed.\n" );
    }
    else
    {
        MyHandleErrorWithExit( "Error during CryptHashData." );
    }
    //-------------------------------------------------------------------
    // Determine the size of the signature and allocate memory.
    dwSigLen = 0;
    if( CryptSignHash(
        hHash,
        AT_SIGNATURE,
        NULL,
        0,
        NULL,
        &dwSigLen ) )
    {
        printf( "Signature length %d found.\n", dwSigLen );
    }
    else
    {
        MyHandleErrorWithExit( "Error during CryptSignHash." );
    }
    //-------------------------------------------------------------------
    // Allocate memory for the signature buffer.
    if( pbSignature = (BYTE *)malloc( dwSigLen ) )
    {
        printf( "Memory allocated for the signature.\n" );
    }
    else
    {
        MyHandleErrorWithExit( "Out of memory." );
    }
    //-------------------------------------------------------------------
    // Sign the hash object.
    if( CryptSignHash(
        hHash,
        AT_SIGNATURE,
        NULL,
        0,
        pbSignature,
        &dwSigLen ) )
    {
        printf( "pbSignature is the hash signature.\n" );
    }
    else
    {
        MyHandleErrorWithExit( "Error during CryptSignHash." );
    }
    //-------------------------------------------------------------------
    // write
    if( WriteDataToRegistry( 
        pbSignature, 
        dwSigLen ) )
    {
        printf( "Data has been wrote to registry\n" );
    }
    else
    {
        MyHandleErrorWithExit( "Error during WriteDataToRegistry" );
    }
    

    //-------------------------------------------------------------------
    // Destroy the hash object.

    if( hHash )
        CryptDestroyHash( hHash );

    printf( "The hash object has been destroyed.\n" );
    printf( "The signing phase of this program is completed.\n\n" );

    //-------------------------------------------------------------------
    // Free memory to be used to store signature.

    if( pbSignature )
        free( pbSignature );

    //-------------------------------------------------------------------
    // Destroy the hash object.

    if( hHash )
        CryptDestroyHash( hHash );

    //-------------------------------------------------------------------
    // Release the provider handle.

    if( hProv )
        CryptReleaseContext( hProv, 0 );
}

void main( void )
{
    Install();
} //  End of main

//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError( char * s )
{
    fprintf( stderr, "An error occurred in running the program. \n" );
    fprintf( stderr, "%s\n", s );
    fprintf( stderr, "Error number %x.\n", GetLastError() );
} // End of MyHandleError

void MyHandleErrorWithExit( char * s )
{
    fprintf( stderr, "An error occurred in running the program. \n" );
    fprintf( stderr, "%s\n", s );
    fprintf( stderr, "Error number %x.\n", GetLastError() );
    fprintf( stderr, "Program terminating. \n" );
    exit( 1 );
} // End of MyHandleError