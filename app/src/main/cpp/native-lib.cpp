#include <jni.h>
#include <string>
#include <dlfcn.h>
#include "cryptoki.h"
#include <sstream>
#include <iomanip>

typedef int(*Connect_usb) (int);
typedef CK_RV (*Initialize)(CK_VOID_PTR);
typedef CK_RV (*GetSlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
typedef CK_RV (*OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR);
typedef CK_RV (*Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (*FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
typedef CK_RV (*GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (*FindObjectsFinal)(CK_SESSION_HANDLE);
typedef CK_RV (*SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*Verify)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*Encrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*Decrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*Logout)(CK_SESSION_HANDLE);
typedef CK_RV (*CloseSession)(CK_SESSION_HANDLE);
typedef CK_RV (*Finalize)(CK_VOID_PTR);

CK_SESSION_HANDLE hSession = 0;
void *dlhandle;

std::string certToHex(CK_BYTE_PTR data, CK_ULONG len) {
    std::stringstream ss;
    ss << std::hex;
    for (CK_ULONG i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];
    return ss.str();
}

void cleanUp() {
    if (dlhandle) {
        dlclose(dlhandle);
        dlhandle = NULL;
    }
}

extern "C" {

JNIEXPORT jint JNICALL
Java_com_example_demopayment_MainActivity_libint(JNIEnv *env, jobject mainActivityInstance, jint fileDescriptor) {
    cleanUp();
    dlhandle = dlopen("liblsusbdemo.so", RTLD_LAZY);
    if (dlhandle == NULL) {
        return -1;
    }
    Connect_usb Connect_usb_test = (Connect_usb) dlsym(dlhandle, "Connect_usb");
    if (Connect_usb_test == NULL) {
        cleanUp();
        return -1;
    }
    int x = Connect_usb_test(fileDescriptor);
    return x;
}

JNIEXPORT jstring JNICALL
Java_com_example_demopayment_MainActivity_login(JNIEnv *env, jobject mainActivityInstance, jstring jStr) {
    cleanUp();
    const char *token_pin = env->GetStringUTFChars(jStr, nullptr);

    dlhandle = dlopen("liblsusbdemo.so", RTLD_LAZY);
    if (dlhandle == NULL) {
        return env->NewStringUTF("Failed to load library");
    }

    Initialize c_initialize = (Initialize) dlsym(dlhandle, "C_Initialize");
    GetSlotList getSlotList = (GetSlotList) dlsym(dlhandle, "C_GetSlotList");
    OpenSession c_openSession = (OpenSession) dlsym(dlhandle, "C_OpenSession");
    Login c_login = (Login) dlsym(dlhandle, "C_Login");

    if (!c_initialize || !getSlotList || !c_openSession || !c_login) {
        cleanUp();
        return env->NewStringUTF("Failed to find symbols");
    }

    CK_RV rv = c_initialize(NULL);
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to initialize PKCS#11");
    }

    CK_SLOT_ID slotlist[10];
    CK_ULONG no_of_slots;
    rv = getSlotList(CK_TRUE, slotlist, &no_of_slots);
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to get total slots");
    }

    rv = c_openSession(slotlist[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to create session");
    }

    rv = c_login(hSession, CKU_USER, (CK_UTF8CHAR_PTR) token_pin, strlen((const char *) token_pin));
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to login");
    }

    return env->NewStringUTF("Login Success");
}

JNIEXPORT jstring JNICALL
Java_com_example_demopayment_MainActivity_readCertificate(JNIEnv *env, jobject mainActivityInstance) {
    dlhandle = dlopen("liblsusbdemo.so", RTLD_LAZY);
    if (dlhandle == NULL) {
        return env->NewStringUTF("Failed to load library");
    }

    FindObjectsInit c_findObjectsInit = (FindObjectsInit) dlsym(dlhandle, "C_FindObjectsInit");
    FindObjects c_findObjects = (FindObjects) dlsym(dlhandle, "C_FindObjects");
    GetAttributeValue c_getAttributeValue = (GetAttributeValue) dlsym(dlhandle, "C_GetAttributeValue");
    FindObjectsFinal c_findObjectsFinal = (FindObjectsFinal) dlsym(dlhandle, "C_FindObjectsFinal");

    if (!c_findObjectsInit || !c_findObjects || !c_findObjectsFinal || !c_getAttributeValue) {
        cleanUp();
        return env->NewStringUTF("Failed to find symbols");
    }

    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_ATTRIBUTE certTemplate[] = {
            {CKA_CLASS, &certClass, sizeof(certClass)},
            {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)}
    };

    CK_RV rv = c_findObjectsInit(hSession, certTemplate, 2);
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to initialize object search");
    }

    CK_OBJECT_HANDLE certObj;
    CK_ULONG objCount;
    rv = c_findObjects(hSession, &certObj, 1, &objCount);
    if (rv != CKR_OK || objCount == 0) {
        c_findObjectsFinal(hSession);
        cleanUp();
        return env->NewStringUTF("Failed to find certificate object");
    }

    rv = c_findObjectsFinal(hSession);
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to finalize object search");
    }

    CK_ATTRIBUTE certValueTemplate[] = {
            {CKA_VALUE, NULL_PTR, 0}
    };

    rv = c_getAttributeValue(hSession, certObj, certValueTemplate, 1);
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to get certificate value size");
    }

    CK_BYTE_PTR certValue = (CK_BYTE_PTR) malloc(certValueTemplate[0].ulValueLen);
    if (certValue == NULL) {
        cleanUp();
        return env->NewStringUTF("Failed to allocate memory for certificate value");
    }

    certValueTemplate[0].pValue = certValue;
    rv = c_getAttributeValue(hSession, certObj, certValueTemplate, 1);
    if (rv != CKR_OK) {
        free(certValue);
        cleanUp();
        return env->NewStringUTF("Failed to get certificate value");
    }

    std::string hexCertValue = certToHex(certValue, certValueTemplate[0].ulValueLen);
    free(certValue);

    jstring jCertValue = env->NewStringUTF(hexCertValue.c_str());
    return jCertValue;
}

JNIEXPORT jstring JNICALL
Java_com_example_demopayment_MainActivity_logout(JNIEnv *env, jobject thiz) {
    dlhandle = dlopen("liblsusbdemo.so", RTLD_LAZY);
    if (dlhandle == NULL) {
        return env->NewStringUTF("Failed to load library");
    }

    Logout logout = (Logout) dlsym(dlhandle, "C_Logout");
    CloseSession closeSession = (CloseSession) dlsym(dlhandle, "C_CloseSession");
    Finalize finalize = (Finalize) dlsym(dlhandle, "C_Finalize");

    if (!logout || !closeSession || !finalize) {
        cleanUp();
        return env->NewStringUTF("Failed to find symbols");
    }

    CK_RV rv = logout(hSession);
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to logout");
    }

    rv = closeSession(hSession);
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to close session");
    }

    rv = finalize(NULL_PTR);
    if (rv != CKR_OK) {
        cleanUp();
        return env->NewStringUTF("Failed to finalize");
    }

    cleanUp();
    return env->NewStringUTF("Logged out Successfully");
}
}




//JNIEXPORT jstring  extern "C" JNICALL
//Java_com_example_demopayment_MainActivity_signData(JNIEnv *env, jobject mainActivityInstance) {
//
//    const jclass mainActivityCls = env->GetObjectClass(mainActivityInstance);
//    const jmethodID jmethodId_PlainText = env->GetMethodID(mainActivityCls, "getPlainText", "()Ljava/lang/String;");
//
//    if(jmethodId_PlainText == nullptr){
//        return (jstring) "Failed to retrieve";
//    }
//
//    jstring jPlainText = (jstring) env->CallObjectMethod(mainActivityInstance, jmethodId_PlainText);
//    plain_data = env->GetStringUTFChars(jPlainText, nullptr);
//
//    // Checking
//    std::string result = std::string(plain_data);
//
//
//    FindObjectsInit c_findObjectsInit = (FindObjectsInit)dlsym(dlhandle, "C_FindObjectsInit");
//    FindObjects c_findObjects = (FindObjects)dlsym(dlhandle, "C_FindObjects");
//    GetAttributeValue c_getAttributeValue = (GetAttributeValue)dlsym(dlhandle, "C_GetAttributeValue");
//    FindObjectsFinal findObjectsFinal = (FindObjectsFinal)dlsym(dlhandle, "C_FindObjectsFinal");
//    SignInit signInit = (SignInit)dlsym(dlhandle, "C_SignInit");
//    Sign sign = (Sign)dlsym(dlhandle, "C_Sign");
//
//    CK_OBJECT_CLASS keyClassPriv = CKO_PRIVATE_KEY;
//    CK_ATTRIBUTE templPriv[] = {{CKA_CLASS, &keyClassPriv, sizeof(keyClassPriv)}};
//    CK_ULONG templPrivateSize = sizeof(templPriv) / sizeof(CK_ATTRIBUTE);
//
//    rv = c_findObjectsInit(hSession, templPriv, templPrivateSize);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to initiate find objects");
//    }
//
//    rv = c_findObjects(hSession, &hObject, 1, &ulObjectCount);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to find objects");
//    }
//
//    CK_UTF8CHAR label[32];
//    CK_ATTRIBUTE readtemplPrivate[] = {
//            {CKA_LABEL, label, sizeof(label)}
//    };
//
//    int tempsize = sizeof(readtemplPrivate)/sizeof(CK_ATTRIBUTE);
//
//    for (CK_ULONG i = 0; i < ulObjectCount; ++i) {
//        rv =  c_getAttributeValue(hSession, hObject, readtemplPrivate, tempsize);
//        if (rv == CKR_OK) {
//            hPrivate = hObject;
//        } else {
//            return env->NewStringUTF("Failed to read objects");
//        }
//    }
//
//    rv = findObjectsFinal(hSession);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to close find objects");
//    }
//
//    //Sign
//    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
//    rv = signInit(hSession, &mech, hPrivate);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to initialize signing");
//    }
//
//    rv = sign(hSession, (CK_BYTE *) plain_data, strlen((const char*)plain_data), signature, &sigLen);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to sign the data");
//    }
//
//    // Convert the signature to a hex string
//    std::string hexSignature;
//    char hexBuffer[3];
//    for (CK_ULONG i = 0; i < sigLen; ++i) {
//        snprintf(hexBuffer, sizeof(hexBuffer), "%02X", signature[i]);
//        hexSignature.append(hexBuffer);
//    }
//
//    return env->NewStringUTF(hexSignature.c_str());
//}
//
//
//JNIEXPORT jstring  extern "C" JNICALL
//Java_com_example_demopayment_MainActivity_verify(JNIEnv *env, jobject thiz) {
//
//    VerifyInit verifyInit = (VerifyInit)dlsym(dlhandle, "C_VerifyInit");
//    Verify verify = (Verify)dlsym(dlhandle, "C_Verify");
//
//    if(signature == NULL_PTR){
//        return env->NewStringUTF("Signature not found");
//    }
//
//    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
//    rv = verifyInit(hSession, &mech, 5000);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to initialize verify");
//    }
//
//    rv = verify(hSession, (CK_BYTE_PTR) plain_data, strlen((const char*)plain_data), signature, sigLen);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to verify the data");
//    }
//
//    return env->NewStringUTF("Verified");
//}
//
//
//JNIEXPORT jstring  extern "C" JNICALL
//Java_com_example_demopayment_MainActivity_encrypt(JNIEnv *env, jobject mainActivityInstance) {
//
//    const jclass mainActivityCls = env->GetObjectClass(mainActivityInstance);
//    const jmethodID jmethodId_PlainText = env->GetMethodID(mainActivityCls, "getPlainText", "()Ljava/lang/String;");
//
//    if(jmethodId_PlainText == nullptr){
//        return (jstring) "Failed to retrieve";
//    }
//
//    jstring jPlainText = (jstring) env->CallObjectMethod(mainActivityInstance, jmethodId_PlainText);
//    plain_data_encrypt = env->GetStringUTFChars(jPlainText, nullptr);
//
//    // Checking
//    std::string result = std::string(plain_data_encrypt);
//
//    EncryptInit encryptInit = (EncryptInit)dlsym(dlhandle, "C_EncryptInit");
//    Encrypt encrypt = (Encrypt)dlsym(dlhandle, "C_Encrypt");
//
//    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
//    rv = encryptInit(hSession, &mech, 5000);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to verify the data");
//    }
//
//    rv = encrypt(hSession, (CK_BYTE_PTR) plain_data_encrypt, sizeof(plain_data_encrypt) - 1, NULL, &encLen);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to verify the data");
//    }
//
//    encrypted = new CK_BYTE[encLen];
//    rv = encrypt(hSession, (CK_BYTE_PTR) plain_data_encrypt, sizeof(plain_data_encrypt) - 1, encrypted, &encLen);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to verify the data");
//    }
//
//    //converting bytes to hex
//    std::string hexEncryptedData;
//    char hexBuffer[3];
//    for (CK_ULONG i = 0; i < encLen; ++i) {
//        snprintf(hexBuffer, sizeof(hexBuffer), "%02X", encrypted[i]);
//        hexEncryptedData.append(hexBuffer);
//    }
//
//    return env->NewStringUTF(hexEncryptedData.c_str());
//}
//
//
//JNIEXPORT jstring  extern "C" JNICALL
//Java_com_example_demopayment_MainActivity_decrypt(JNIEnv *env, jobject thiz) {
//
//    if(encrypted == NULL_PTR){
//        return env->NewStringUTF("Encrypted data not found");
//    }
//
//    DecryptInit decryptInit = (DecryptInit)dlsym(dlhandle, "C_DecryptInit");
//    Decrypt decrypt = (Decrypt)dlsym(dlhandle, "C_Decrypt");
//
//    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
//    rv = decryptInit(hSession, &mech, hPrivate);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to logout");
//    }
//
//    rv = decrypt(hSession, encrypted, encLen, NULL, &decLen);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to logout");
//    }
//
//    decrypted = new CK_BYTE[decLen];
//    rv = decrypt(hSession, encrypted, encLen, decrypted, &decLen);
//    if (rv != CKR_OK) {
//        return env->NewStringUTF("Failed to logout");
//    }
//
//    //converting bytes to hex
//    std::string hexDecryptedData;
//    char hexBuffer[3];
//    for (CK_ULONG i = 0; i < decLen; ++i) {
//        snprintf(hexBuffer, sizeof(hexBuffer), "%02X", decrypted[i]);
//        hexDecryptedData.append(hexBuffer);
//    }
//
//    return env->NewStringUTF(hexDecryptedData.c_str());
//}
//
//
