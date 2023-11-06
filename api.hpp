namespace api {
	extern unsigned long djn1l(unsigned char* str);
	extern unsigned long djn1lUnicode(const wchar_t* str);
	extern uint64_t getFuncApi(unsigned long dll_hash, unsigned long function_hash);
	template<typename T>
    T get(unsigned long dll_hash, unsigned long func_hash) {
        return reinterpret_cast<T>(getFuncApi(dll_hash, func_hash));
    }
}