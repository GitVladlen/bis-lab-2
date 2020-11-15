#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void MyHandleError( char * s );

#define TOTAL_BYTES_READ    1024
#define OFFSET_BYTES 1024

#include "App.h"

#include <sstream>

BOOL ReadUserInfoFromRegistry( HKEY hKeyParent, LPSTR subkey, LPCSTR valueName, PBYTE * readData, DWORD * readDataLen )
{
    HKEY hKey;
    DWORD len = TOTAL_BYTES_READ;
    *readDataLen = len;
    PBYTE readBuffer = (PBYTE)malloc( sizeof( PBYTE ) * len );
    if( readBuffer == NULL )
        return FALSE;
    //Check if the registry exists
    DWORD Ret = RegOpenKeyEx(
        hKeyParent,
        subkey,
        0,
        KEY_READ,
        &hKey
    );
    if( Ret == ERROR_SUCCESS )
    {
        Ret = RegQueryValueEx(
            hKey,
            valueName,
            NULL,
            NULL,
            (BYTE *)readBuffer,
            readDataLen
        );
        while( Ret == ERROR_MORE_DATA )
        {
            // Get a buffer that is big enough.
            len += OFFSET_BYTES;
            readBuffer = (PBYTE)realloc( readBuffer, len );
            *readDataLen = len;
            Ret = RegQueryValueEx(
                hKey,
                valueName,
                NULL,
                NULL,
                (BYTE *)readBuffer,
                readDataLen
            );
        }
        if( Ret != ERROR_SUCCESS )
        {
            RegCloseKey( hKey );
            return false;;
        }
        *readData = readBuffer;
        RegCloseKey( hKey );
        return true;
    }
    else
    {
        return false;
    }
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


bool Check()
{
    //-------------------------------------------------------------------
    // Get data for hash
    std::string data = GetDataForHash();

    printf( "Data for hash '%s'\n", data.c_str() );

    //-------------------------------------------------------------------
    // Declare and initialize variables.

    LPSTR subKey = "Software\\Efremova";
    LPCSTR valueName = "Signature";

    PBYTE pbSignature = nullptr;
    DWORD dwSigLen = 0;

    //-------------------------------------------------------------------
    // Read signature from registry

    if( ReadUserInfoFromRegistry(
        HKEY_CURRENT_USER,
        subKey,
        valueName,
        &pbSignature,
        &dwSigLen ) )
    {
        printf( "The signature has been read.\n" );
    }
    else
    {
        MyHandleError( "Error during ReadUserInfoFromRegistry." );
        return false;
    }

    //-------------------------------------------------------------------
    // Declare and initialize variables.

    HCRYPTPROV hProv;
    BYTE * pbBuffer = (BYTE *)data.c_str();
    DWORD dwBufferLen = strlen( (char *)pbBuffer ) + 1;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    HCRYPTKEY hPubKey;
    BYTE * pbKeyBlob;
    DWORD dwBlobLen;

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
        MyHandleError( "Error during CryptAcquireContext." );
        if( pbSignature )
            free( pbSignature );
        return false;
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
        MyHandleError( "Error during CryptGetUserKey for signkey." );
        if( pbSignature )
            free( pbSignature );
        if( hProv )
            CryptReleaseContext( hProv, 0 );
        return false;
    }
    ////-------------------------------------------------------------------
    // Export the public key. Here the public key is exported to a 
    // PUBLICKEYBOLB so that the receiver of the signed hash can
    // verify the signature. This BLOB could be written to a file and
    // sent to another user.

    if( CryptExportKey(
        hKey,
        NULL,
        PUBLICKEYBLOB,
        0,
        NULL,
        &dwBlobLen ) )
    {
        printf( "Size of the BLOB for the public key determined. \n" );
    }
    else
    {
        MyHandleError( "Error computing BLOB length." );
        if( pbSignature )
            free( pbSignature );
        if( hProv )
            CryptReleaseContext( hProv, 0 );
        return false;
    }
    //-------------------------------------------------------------------
    // Allocate memory for the pbKeyBlob.

    if( pbKeyBlob = (BYTE *)malloc( dwBlobLen ) )
    {
        printf( "Memory has been allocated for the BLOB. \n" );
    }
    else
    {
        MyHandleError( "Out of memory. \n" );
        if( pbSignature )
            free( pbSignature );
        if( hProv )
            CryptReleaseContext( hProv, 0 );
        return false;
    }
    //-------------------------------------------------------------------
    // Do the actual exporting into the key BLOB.

    if( CryptExportKey(
        hKey,
        NULL,
        PUBLICKEYBLOB,
        0,
        pbKeyBlob,
        &dwBlobLen ) )
    {
        printf( "Contents have been written to the BLOB. \n" );
    }
    else
    {
        MyHandleError( "Error during CryptExportKey." );
        if( pbSignature )
            free( pbSignature );
        if( hProv )
            CryptReleaseContext( hProv, 0 );
        return false;
    }
    //-------------------------------------------------------------------
    // In the second phase, the hash signature is verified.
    // This would most often be done by a different user in a
    // separate program. The hash, signature, and the PUBLICKEYBLOB
    // would be read from a file, an email message, 
    // or some other source.

    // Here, the original pbBuffer, pbSignature, szDescription. 
    // pbKeyBlob, and their lengths are used.

    // The contents of the pbBuffer must be the same data 
    // that was originally signed.

    //-------------------------------------------------------------------
    // Get the public key of the user who created the digital signature 
    // and import it into the CSP by using CryptImportKey. This returns
    // a handle to the public key in hPubKey.

    if( CryptImportKey(
        hProv,
        pbKeyBlob,
        dwBlobLen,
        0,
        0,
        &hPubKey ) )
    {
        printf( "The key has been imported.\n" );
    }
    else
    {
        MyHandleError( "Public key import failed." );
        if( pbSignature )
            free( pbSignature );
        if( hProv )
            CryptReleaseContext( hProv, 0 );
        return false;
    }
    //-------------------------------------------------------------------
    // Create a new hash object.

    if( CryptCreateHash(
        hProv,
        CALG_MD5,
        0,
        0,
        &hHash ) )
    {
        printf( "The hash object has been recreated. \n" );
    }
    else
    {
        MyHandleError( "Error during CryptCreateHash." );
        if( pbSignature )
            free( pbSignature );
        if( hProv )
            CryptReleaseContext( hProv, 0 );
        return false;
    }
    //-------------------------------------------------------------------
    // Compute the cryptographic hash of the buffer.

    if( CryptHashData(
        hHash,
        pbBuffer,
        dwBufferLen,
        0 ) )
    {
        printf( "The new hash has been created.\n" );
    }
    else
    {
        MyHandleError( "Error during CryptHashData." );
        if( pbSignature )
            free( pbSignature );
        if( hHash )
            CryptDestroyHash( hHash );
        if( hProv )
            CryptReleaseContext( hProv, 0 );
        return false;
    }
    //-------------------------------------------------------------------
    // Validate the digital signature.

    if( CryptVerifySignature(
        hHash,
        pbSignature,
        dwSigLen,
        hPubKey,
        NULL,
        0 ) )
    {
        printf( "The signature has been verified.\n" );
    }
    else
    {
        printf( "Signature not validated!\n" );
        if( pbSignature )
            free( pbSignature );
        if( hHash )
            CryptDestroyHash( hHash );
        if( hProv )
            CryptReleaseContext( hProv, 0 );
        return false;
    }
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

    return true;
}

void main()
{
    if( Check() == false )
    {
        printf( "Check signature from registry failed!\n" );
        return;
    }
	App app = App();
	app.run();
}

void MyHandleError( char * s )
{
    fprintf( stderr, "An error occurred in running the program. \n" );
    fprintf( stderr, "%s\n", s );
    fprintf( stderr, "Error number %x.\n", GetLastError() );
} // End of MyHandleError