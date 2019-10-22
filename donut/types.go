package donut

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/google/uuid"
)

const (
	DONUT_MAX_PARAM   = 8 // maximum number of parameters passed to method
	DONUT_MAX_NAME    = 256
	DONUT_MAX_DLL     = 8 // maximum number of DLL supported by instance
	DONUT_MAX_URL     = 256
	DONUT_MAX_MODNAME = 8
	DONUT_SIG_LEN     = 8 // 64-bit string to verify decryption ok
	DONUT_VER_LEN     = 32
	DONUT_DOMAIN_LEN  = 8

	MARU_MAX_STR  = 64
	MARU_BLK_LEN  = 16
	MARU_HASH_LEN = 8
	MARU_IV_LEN   = 8

	DONUT_RUNTIME_NET4 = "v4.0.30319"

	NTDLL_DLL    = "ntdll.dll"
	KERNEL32_DLL = "kernel32.dll"
	ADVAPI32_DLL = "advapi32.dll"
	CRYPT32_DLL  = "crypt32.dll"
	MSCOREE_DLL  = "mscoree.dll"
	OLE32_DLL    = "ole32.dll"
	OLEAUT32_DLL = "oleaut32.dll"
	WININET_DLL  = "wininet.dll"
	COMBASE_DLL  = "combase.dll"
	USER32_DLL   = "user32.dll"
	SHLWAPI_DLL  = "shlwapi.dll"
)

// DonutArch - CPU architecture type (32, 64, or 32+64)
type DonutArch int

const (
	// X32 - 32bit
	X32 DonutArch = iota
	// X64 - 64 bit
	X64
	// X84 - 32+64 bit
	X84
)

type ModuleType int

const (
	DONUT_MODULE_NET_DLL ModuleType = 1 // .NET DLL. Requires class and method
	DONUT_MODULE_NET_EXE            = 2 // .NET EXE. Executes Main if no class and method provided
	DONUT_MODULE_DLL                = 3 // Unmanaged DLL, function is optional
	DONUT_MODULE_EXE                = 4 // Unmanaged EXE
	DONUT_MODULE_VBS                = 5 // VBScript
	DONUT_MODULE_JS                 = 6 // JavaScript or JScript
	DONUT_MODULE_XSL                = 7 // XSL with JavaScript/JScript or VBscript embedded
)

type InstanceType int

const (
	DONUT_INSTANCE_PIC InstanceType = 1 // Self-contained
	DONUT_INSTANCE_URL              = 2 // Download from remote server
)

type DonutConfig struct {
	Arch       DonutArch
	Type       ModuleType
	InstType   InstanceType
	Parameters string // separated by , or ;

	NoCrypto   bool
	DotNetMode bool

	Domain  string // .NET stuff
	Class   string
	Method  string // Used by Native DLL and .NET DLL
	Runtime string
	Bypass  int

	Module     *DonutModule
	ModuleName string
	URL        string
	ModuleMac  uint64
	ModuleData *bytes.Buffer

	inst    *DonutInstance
	instLen uint32
}

type DonutModule struct {
	ModType    uint32                                  // EXE, DLL, JS, VBS, XSL
	Runtime    [DONUT_MAX_NAME]uint16                  // runtime version for .NET EXE/DLL (donut max name = 256)
	Domain     [DONUT_MAX_NAME]uint16                  // domain name to use for .NET EXE/DLL
	Cls        [DONUT_MAX_NAME]uint16                  // name of class and optional namespace for .NET EXE/DLL
	Method     [DONUT_MAX_NAME * 2]byte                // name of method to invoke for .NET DLL or api for unmanaged DLL
	ParamCount uint32                                  // number of parameters for DLL/EXE
	Param      [DONUT_MAX_PARAM][DONUT_MAX_NAME]uint16 // string parameters for DLL/EXE (donut max parm = 8)
	Sig        [DONUT_MAX_NAME]byte                    // random string to verify decryption
	Mac        uint64                                  // to verify decryption was ok
	Len        uint64                                  // size of EXE/DLL/XSL/JS/VBS file
	Data       [4]byte                                 // data of EXE/DLL/XSL/JS/VBS file
}

func WriteField(w *bytes.Buffer, name string, i interface{}) {
	binary.Write(w, binary.LittleEndian, i)
}

func (mod *DonutModule) WriteTo(w *bytes.Buffer) {
	WriteField(w, "ModType", mod.ModType)
	binary.Write(w, binary.LittleEndian, mod.Runtime)
	//log.Println("Runtime", w.Len(), w.Len()-baseLen)
	binary.Write(w, binary.LittleEndian, mod.Domain)
	//log.Println("Domain", w.Len(), w.Len()-baseLen)
	binary.Write(w, binary.LittleEndian, mod.Cls)
	//log.Println("CLS", w.Len(), w.Len()-baseLen)
	w.Write(mod.Method[:len(mod.Method)])
	//log.Println("Method", w.Len(), w.Len()-baseLen)

	binary.Write(w, binary.LittleEndian, mod.ParamCount)
	//log.Println("ParamCount", w.Len(), w.Len()-baseLen)
	binary.Write(w, binary.LittleEndian, mod.Param)
	//log.Println("Param", w.Len(), w.Len()-baseLen)
	w.Write(mod.Sig[:len(mod.Sig)])
	//log.Println("Sig", w.Len(), w.Len()-baseLen)
	binary.Write(w, binary.LittleEndian, mod.Mac)
	//log.Println("Mac", w.Len(), w.Len()-baseLen)
	binary.Write(w, binary.LittleEndian, mod.Len)
}

type DonutInstance struct {
	Len uint32 // total size of instance

	//Key  DonutCrypt // decrypts instance (32 bytes total = 16+16)
	KeyMk  [CipherKeyLen]byte   // master key
	KeyCtr [CipherBlockLen]byte // counter + nonce

	Iv   [8]byte    // the 64-bit initial value for maru hash
	Hash [64]uint64 // holds up to 64 api hashes/addrs {api}

	// everything from here is encrypted
	ApiCount uint32                  // the 64-bit hashes of API required for instance to work
	DllCount uint32                  // the number of DLL to load before resolving API
	DllName  [DONUT_MAX_DLL][32]byte // a list of DLL strings to load

	S [8]byte // amsi.dll

	Bypass         uint32   // indicates behaviour of byassing AMSI/WLDP
	Clr            [8]byte  // clr.dll
	Wldp           [16]byte // wldp.dll
	WldpQuery      [32]byte // WldpQueryDynamicCodeTrust
	WldpIsApproved [32]byte // WldpIsClassInApprovedList
	AmsiInit       [16]byte // AmsiInitialize
	AmsiScanBuf    [16]byte // AmsiScanBuffer
	AmsiScanStr    [16]byte // AmsiScanString

	Wscript     [8]uint16  // WScript
	Wscript_exe [16]uint16 // wscript.exe

	XIID_IUnknown  uuid.UUID
	XIID_IDispatch uuid.UUID

	//  GUID required to load .NET assemblies
	XCLSID_CLRMetaHost    uuid.UUID
	XIID_ICLRMetaHost     uuid.UUID
	XIID_ICLRRuntimeInfo  uuid.UUID
	XCLSID_CorRuntimeHost uuid.UUID
	XIID_ICorRuntimeHost  uuid.UUID
	XIID_AppDomain        uuid.UUID

	//  GUID required to run VBS and JS files
	XCLSID_ScriptLanguage        uuid.UUID // vbs or js
	XIID_IHost                   uuid.UUID // wscript object
	XIID_IActiveScript           uuid.UUID // engine
	XIID_IActiveScriptSite       uuid.UUID // implementation
	XIID_IActiveScriptSiteWindow uuid.UUID // basic GUI stuff
	XIID_IActiveScriptParse32    uuid.UUID // parser
	XIID_IActiveScriptParse64    uuid.UUID

	//  GUID required to run XSL files
	XCLSID_DOMDocument30 uuid.UUID
	XIID_IXMLDOMDocument uuid.UUID
	XIID_IXMLDOMNode     uuid.UUID

	Type uint32 // DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL

	Url [DONUT_MAX_URL]byte // staging server hosting donut module
	Req [8]byte             // just a buffer for "GET"

	Sig [DONUT_MAX_NAME]byte // string to hash
	Mac uint64               // to verify decryption ok

	ModKeyMk  [CipherKeyLen]byte   // master key
	ModKeyCtr [CipherBlockLen]byte // counter + nonce

	Mod_len uint64 // total size of module
}

func (inst *DonutInstance) WriteTo(w *bytes.Buffer) {
	//start := w.Len()
	WriteField(w, "Len", inst.Len)
	for i := 0; i < 4; i++ { // padding to 8-byte alignment after 4 byte field
		w.WriteByte(0)
	}
	WriteField(w, "KeyMk", inst.KeyMk)
	WriteField(w, "KeyCtr", inst.KeyCtr)
	WriteField(w, "Iv", inst.Iv)

	WriteField(w, "Hash", inst.Hash)
	WriteField(w, "ApiCount", inst.ApiCount)
	WriteField(w, "DllCount", inst.DllCount)
	WriteField(w, "DllName", inst.DllName)
	WriteField(w, "S", inst.S)
	WriteField(w, "Bypass", inst.Bypass)
	WriteField(w, "Clr", inst.Clr)
	WriteField(w, "Wldp", inst.Wldp)
	WriteField(w, "WldpQuery", inst.WldpQuery)
	WriteField(w, "WldpIsApproved", inst.WldpIsApproved)

	binary.Write(w, binary.LittleEndian, inst.AmsiInit)
	binary.Write(w, binary.LittleEndian, inst.AmsiScanBuf)
	binary.Write(w, binary.LittleEndian, inst.AmsiScanStr)

	binary.Write(w, binary.LittleEndian, inst.Wscript)
	binary.Write(w, binary.LittleEndian, inst.Wscript_exe)

	binary.Write(w, binary.LittleEndian, inst.XIID_IUnknown)
	binary.Write(w, binary.LittleEndian, inst.XIID_IDispatch)

	swapUUID(w, inst.XCLSID_CLRMetaHost)
	swapUUID(w, inst.XIID_ICLRMetaHost)
	swapUUID(w, inst.XIID_ICLRRuntimeInfo)
	swapUUID(w, inst.XCLSID_CorRuntimeHost)
	swapUUID(w, inst.XIID_ICorRuntimeHost)
	swapUUID(w, inst.XIID_AppDomain)

	swapUUID(w, inst.XCLSID_ScriptLanguage)
	swapUUID(w, inst.XIID_IHost)
	swapUUID(w, inst.XIID_IActiveScript)
	swapUUID(w, inst.XIID_IActiveScriptSite)
	swapUUID(w, inst.XIID_IActiveScriptSiteWindow)
	swapUUID(w, inst.XIID_IActiveScriptParse32)
	swapUUID(w, inst.XIID_IActiveScriptParse64)

	swapUUID(w, inst.XCLSID_DOMDocument30)
	swapUUID(w, inst.XIID_IXMLDOMDocument)
	swapUUID(w, inst.XIID_IXMLDOMNode)

	binary.Write(w, binary.LittleEndian, inst.Type)
	binary.Write(w, binary.LittleEndian, inst.Url)
	binary.Write(w, binary.LittleEndian, inst.Req)
	binary.Write(w, binary.LittleEndian, inst.Sig)
	binary.Write(w, binary.LittleEndian, inst.Mac)
	binary.Write(w, binary.LittleEndian, inst.ModKeyMk)
	binary.Write(w, binary.LittleEndian, inst.ModKeyCtr)
	binary.Write(w, binary.LittleEndian, inst.Mod_len)
}

type API_IMPORT struct {
	Module string
	Name   string
}

var api_imports = []API_IMPORT{
	API_IMPORT{Module: KERNEL32_DLL, Name: "LoadLibraryA"},
	API_IMPORT{Module: KERNEL32_DLL, Name: "GetProcAddress"},
	API_IMPORT{Module: KERNEL32_DLL, Name: "GetModuleHandleA"},
	API_IMPORT{Module: KERNEL32_DLL, Name: "VirtualAlloc"},
	API_IMPORT{Module: KERNEL32_DLL, Name: "VirtualFree"},
	API_IMPORT{Module: KERNEL32_DLL, Name: "VirtualQuery"},
	API_IMPORT{Module: KERNEL32_DLL, Name: "VirtualProtect"},
	API_IMPORT{Module: KERNEL32_DLL, Name: "Sleep"},
	API_IMPORT{Module: KERNEL32_DLL, Name: "MultiByteToWideChar"},
	API_IMPORT{Module: KERNEL32_DLL, Name: "GetUserDefaultLCID"},

	API_IMPORT{Module: OLEAUT32_DLL, Name: "SafeArrayCreate"},
	API_IMPORT{Module: OLEAUT32_DLL, Name: "SafeArrayCreateVector"},

	API_IMPORT{Module: OLEAUT32_DLL, Name: "SafeArrayPutElement"},
	API_IMPORT{Module: OLEAUT32_DLL, Name: "SafeArrayDestroy"},
	API_IMPORT{Module: OLEAUT32_DLL, Name: "SafeArrayGetLBound"},
	API_IMPORT{Module: OLEAUT32_DLL, Name: "SafeArrayGetUBound"},
	API_IMPORT{Module: OLEAUT32_DLL, Name: "SysAllocString"},
	API_IMPORT{Module: OLEAUT32_DLL, Name: "SysFreeString"},
	API_IMPORT{Module: OLEAUT32_DLL, Name: "LoadTypeLib"},

	API_IMPORT{Module: WININET_DLL, Name: "InternetCrackUrlA"},
	API_IMPORT{Module: WININET_DLL, Name: "InternetOpenA"},
	API_IMPORT{Module: WININET_DLL, Name: "InternetConnectA"},
	API_IMPORT{Module: WININET_DLL, Name: "InternetSetOptionA"},
	API_IMPORT{Module: WININET_DLL, Name: "InternetReadFile"},
	API_IMPORT{Module: WININET_DLL, Name: "InternetCloseHandle"},
	API_IMPORT{Module: WININET_DLL, Name: "HttpOpenRequestA"},
	API_IMPORT{Module: WININET_DLL, Name: "HttpSendRequestA"},
	API_IMPORT{Module: WININET_DLL, Name: "HttpQueryInfoA"},

	API_IMPORT{Module: MSCOREE_DLL, Name: "CorBindToRuntime"},
	API_IMPORT{Module: MSCOREE_DLL, Name: "CLRCreateInstance"},

	API_IMPORT{Module: OLE32_DLL, Name: "CoInitializeEx"},
	API_IMPORT{Module: OLE32_DLL, Name: "CoCreateInstance"},
	API_IMPORT{Module: OLE32_DLL, Name: "CoUninitialize"},
}

// required to load .NET assemblies
var ( //the first 6 bytes of these were int32+int16, need to be swapped on write
	xCLSID_CorRuntimeHost = uuid.UUID{
		0xcb, 0x2f, 0x67, 0x23, 0xab, 0x3a, 0x11, 0xd2, 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}

	xIID_ICorRuntimeHost = uuid.UUID{
		0xcb, 0x2f, 0x67, 0x22, 0xab, 0x3a, 0x11, 0xd2, 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}

	xCLSID_CLRMetaHost = uuid.UUID{
		0x92, 0x80, 0x18, 0x8d, 0x0e, 0x8e, 0x48, 0x67, 0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}

	xIID_ICLRMetaHost = uuid.UUID{
		0xD3, 0x32, 0xDB, 0x9E, 0xB9, 0xB3, 0x41, 0x25, 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}

	xIID_ICLRRuntimeInfo = uuid.UUID{
		0xBD, 0x39, 0xD1, 0xD2, 0xBA, 0x2F, 0x48, 0x6a, 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}

	xIID_AppDomain = uuid.UUID{
		0x05, 0xF6, 0x96, 0xDC, 0x2B, 0x29, 0x36, 0x63, 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}

	// required to load VBS and JS files
	xIID_IUnknown = uuid.UUID{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

	xIID_IDispatch = uuid.UUID{
		0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

	xIID_IHost = uuid.UUID{
		0x91, 0xaf, 0xbd, 0x1b, 0x5f, 0xeb, 0x43, 0xf5, 0xb0, 0x28, 0xe2, 0xca, 0x96, 0x06, 0x17, 0xec}

	xIID_IActiveScript = uuid.UUID{
		0xbb, 0x1a, 0x2a, 0xe1, 0xa4, 0xf9, 0x11, 0xcf, 0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}

	xIID_IActiveScriptSite = uuid.UUID{
		0xdb, 0x01, 0xa1, 0xe3, 0xa4, 0x2b, 0x11, 0xcf, 0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}

	xIID_IActiveScriptSiteWindow = uuid.UUID{
		0xd1, 0x0f, 0x67, 0x61, 0x83, 0xe9, 0x11, 0xcf, 0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}

	xIID_IActiveScriptParse32 = uuid.UUID{
		0xbb, 0x1a, 0x2a, 0xe2, 0xa4, 0xf9, 0x11, 0xcf, 0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}

	xIID_IActiveScriptParse64 = uuid.UUID{
		0xc7, 0xef, 0x76, 0x58, 0xe1, 0xee, 0x48, 0x0e, 0x97, 0xea, 0xd5, 0x2c, 0xb4, 0xd7, 0x6d, 0x17}

	xCLSID_VBScript = uuid.UUID{
		0xB5, 0x4F, 0x37, 0x41, 0x5B, 0x07, 0x11, 0xcf, 0xA4, 0xB0, 0x00, 0xAA, 0x00, 0x4A, 0x55, 0xE8}

	xCLSID_JScript = uuid.UUID{
		0xF4, 0x14, 0xC2, 0x60, 0x6A, 0xC0, 0x11, 0xCF, 0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58}

	// required to load XSL files
	xCLSID_DOMDocument30 = uuid.UUID{
		0xf5, 0x07, 0x8f, 0x32, 0xc5, 0x51, 0x11, 0xd3, 0x89, 0xb9, 0x00, 0x00, 0xf8, 0x1f, 0xe2, 0x21}

	xIID_IXMLDOMDocument = uuid.UUID{
		0x29, 0x33, 0xBF, 0x81, 0x7B, 0x36, 0x11, 0xD2, 0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}

	xIID_IXMLDOMNode = uuid.UUID{
		0x29, 0x33, 0xbf, 0x80, 0x7b, 0x36, 0x11, 0xd2, 0xb2, 0x0e, 0x00, 0xc0, 0x4f, 0x98, 0x3e, 0x60}
)

func swapUUID(w io.Writer, u uuid.UUID) {
	bu := new(bytes.Buffer)
	binary.Write(bu, binary.LittleEndian, u)
	var a uint32
	var b, c uint16
	binary.Read(bu, binary.BigEndian, &a)
	binary.Read(bu, binary.BigEndian, &b)
	binary.Read(bu, binary.BigEndian, &c)
	binary.Write(w, binary.LittleEndian, a)
	binary.Write(w, binary.LittleEndian, b)
	binary.Write(w, binary.LittleEndian, c)
	bu.WriteTo(w)
}
