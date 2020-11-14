//--------------------------------------------------------------------
// Copyright (C) Microsoft.  All rights reserved.
// Example of signing a hash and 
// verifying the hash signature.
#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void MyHandleError( char * s );

#define TOTAL_BYTES_READ    1024
#define OFFSET_BYTES 1024

/*
    TODO:
        - READ SIGNATURE FROM REGISTRY
        - CHECK SIGNATURE AND HASH
*/

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

BOOL WriteStringInRegistry( HKEY hKeyParent, LPSTR subkey, LPCSTR valueName, CONST BYTE * lpData, DWORD cbData )
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
    if( WriteStringInRegistry(
        HKEY_CURRENT_USER,
        subKey,
        valueName,
        lpData,
        cbData ) )
    {
        printf( "String data has been wrote to registry.\n" );
    }
    else
    {
        MyHandleError( "Error during writeStringInRegistry." );
        return FALSE;
    }

    return TRUE;
}

//read customer infromation from the registry
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

void Install()
{
    //-------------------------------------------------------------------
    // Declare and initialize variables.
    HCRYPTPROV hProv;
    BYTE * pbBuffer = (BYTE *)"The data that is to be hashed and signed.";
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
        MyHandleError( "Error during CryptAcquireContext." );
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
        MyHandleError( "Error during CryptCreateHash." );
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
        MyHandleError( "Error during CryptHashData." );
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
        MyHandleError( "Error during CryptSignHash." );
    }
    //-------------------------------------------------------------------
    // Allocate memory for the signature buffer.
    if( pbSignature = (BYTE *)malloc( dwSigLen ) )
    {
        printf( "Memory allocated for the signature.\n" );
    }
    else
    {
        MyHandleError( "Out of memory." );
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
        MyHandleError( "Error during CryptSignHash." );
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
        MyHandleError( "Error during WriteDataToRegistry" );
    }
    

    //-------------------------------------------------------------------
    // Destroy the hash object.

    //if( hHash )
    //    CryptDestroyHash( hHash );

    //printf( "The hash object has been destroyed.\n" );
    //printf( "The signing phase of this program is completed.\n\n" );

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

void Check()
{
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
    }

    //-------------------------------------------------------------------
    // Declare and initialize variables.

    HCRYPTPROV hProv;
    BYTE * pbBuffer = (BYTE *)"The data that is to be hashed and signed.";
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
}

void GrabData()
{
    /*
        mouse btn count | screen height
	        nIndex = SM_CMOUSEBUTTONS
	        nIndex = SM_CYSCREEN
	        int GetSystemMetrics(int nIndex);
        disk devices kit
	        DWORD GetLogicalDriveStrings(DWORN nBufferLength, LPTSTR lpBuffer);
        app disk data: file system (lpFileSystemNameBuffer)
	        BOOL GetVolumeInformation(LPCTSTR lpRootPathName,
		        LPTSTR lpVolumeNameBuffer,
		        DWORD nVolumeNameSize,
		        LPDWORD lpVolumeSerialNumber,
		        LPDWORD lpMaximumComponentLength,
		        LPDWORD lpFileSystemFlags,
		        LPTSTR lpFileSystemNameBuffer,
		        DWORD nFileSystemNameSize)
    */

    int mouseButtons = GetSystemMetrics( SM_CMOUSEBUTTONS );
    printf( "mouseButtons = '%d'\n", mouseButtons );

    int screenHeight = GetSystemMetrics( SM_CYSCREEN );
    printf( "screenHeight = '%d'\n", screenHeight );

    const DWORD nBufferLength = 32;
    CHAR lpBuffer[nBufferLength] = { '\0' };

    if( GetLogicalDriveStrings( nBufferLength, lpBuffer ) != 0 )
    {
        printf( "screenHeight = '%s'\n", lpBuffer );
    }
}

void main( void )
{
    GrabData();
    //Install();
    //Check();
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
    fprintf( stderr, "Program terminating. \n" );
    exit( 1 );
} // End of MyHandleError