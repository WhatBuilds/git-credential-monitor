"""macOS metadata enumeration and deletion by exact persistent item reference.

References and account metadata stay in memory and never enter monitor reports.
No password data is requested. Deletion is called only after desktop confirmation.
"""
import ctypes as C


class KeychainError(RuntimeError):
    def __init__(self, operation, status):
        self.status = int(status)
        super().__init__(f"{operation} failed (macOS status {self.status})")


class Keychain:
    def __init__(self):
        self.cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.sec = C.CDLL('/System/Library/Frameworks/Security.framework/Security')
        ptr, index = C.c_void_p, C.c_long
        signatures = {
            'CFDictionaryCreate': (ptr, [ptr, C.POINTER(ptr), C.POINTER(ptr), index, ptr, ptr]),
            'CFDictionaryGetValue': (ptr, [ptr, ptr]),
            'CFArrayCreate': (ptr, [ptr, C.POINTER(ptr), index, ptr]),
            'CFArrayGetCount': (index, [ptr]),
            'CFArrayGetValueAtIndex': (ptr, [ptr, index]),
            'CFGetTypeID': (C.c_ulong, [ptr]),
            'CFStringGetTypeID': (C.c_ulong, []),
            'CFDataGetTypeID': (C.c_ulong, []),
            'CFArrayGetTypeID': (C.c_ulong, []),
            'CFDictionaryGetTypeID': (C.c_ulong, []),
            'CFStringGetLength': (index, [ptr]),
            'CFStringGetCString': (C.c_bool, [ptr, ptr, index, C.c_uint32]),
            'CFDataGetLength': (index, [ptr]),
            'CFDataGetBytePtr': (ptr, [ptr]),
            'CFDataCreate': (ptr, [ptr, ptr, index]),
            'CFRelease': (None, [ptr]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.cf, name)
            function.restype, function.argtypes = result, args
        self.sec.SecItemCopyMatching.argtypes = [ptr, C.POINTER(ptr)]
        self.sec.SecItemCopyMatching.restype = C.c_int32
        self.sec.SecItemDelete.argtypes = [ptr]
        self.sec.SecItemDelete.restype = C.c_int32

    def constant(self, name):
        return C.c_void_p.in_dll(self.cf if name.startswith('kCF') else self.sec, name).value

    def callbacks(self, name):
        return C.addressof(C.c_byte.in_dll(self.cf, name))

    def dictionary(self, pairs):
        keys = (C.c_void_p * len(pairs))(*(self.constant(k) for k, _ in pairs))
        values = (C.c_void_p * len(pairs))(*(v for _, v in pairs))
        return self.cf.CFDictionaryCreate(None, keys, values, len(pairs),
                                         self.callbacks('kCFTypeDictionaryKeyCallBacks'),
                                         self.callbacks('kCFTypeDictionaryValueCallBacks'))

    def value(self, item, name):
        return self.cf.CFDictionaryGetValue(item, self.constant(name))

    def string(self, value):
        if not value or self.cf.CFGetTypeID(value) != self.cf.CFStringGetTypeID():
            return ''
        buf = C.create_string_buffer(self.cf.CFStringGetLength(value) * 4 + 1)
        if not self.cf.CFStringGetCString(value, buf, len(buf), 0x08000100):
            return ''
        return buf.value.decode('utf-8')

    def items(self):
        items = []
        for kind in ('kSecClassGenericPassword', 'kSecClassInternetPassword'):
            query = self.dictionary([
                ('kSecClass', self.constant(kind)),
                ('kSecMatchLimit', self.constant('kSecMatchLimitAll')),
                ('kSecReturnAttributes', self.constant('kCFBooleanTrue')),
                ('kSecReturnPersistentRef', self.constant('kCFBooleanTrue')),
            ])
            result = C.c_void_p()
            try:
                status = self.sec.SecItemCopyMatching(query, C.byref(result))
                if status == -25300:  # errSecItemNotFound
                    continue
                if status != 0 or not result.value:
                    raise KeychainError('Keychain metadata query', status)
                if self.cf.CFGetTypeID(result) != self.cf.CFArrayGetTypeID():
                    raise RuntimeError('Unexpected Keychain result')
                for i in range(self.cf.CFArrayGetCount(result)):
                    item = self.cf.CFArrayGetValueAtIndex(result, i)
                    if self.cf.CFGetTypeID(item) != self.cf.CFDictionaryGetTypeID():
                        raise RuntimeError('Unexpected Keychain item')
                    ref = self.value(item, 'kSecValuePersistentRef')
                    if not ref or self.cf.CFGetTypeID(ref) != self.cf.CFDataGetTypeID():
                        continue
                    identity = C.string_at(self.cf.CFDataGetBytePtr(ref), self.cf.CFDataGetLength(ref))
                    if not identity:
                        continue
                    metadata = {key: self.string(self.value(item, attr)) for key, attr in (
                        ('service', 'kSecAttrService'), ('server', 'kSecAttrServer'),
                        ('label', 'kSecAttrLabel'), ('description', 'kSecAttrDescription'),
                        ('account', 'kSecAttrAccount'))}
                    items.append(dict(metadata, reference=identity, kind=kind))
            finally:
                if result.value:
                    self.cf.CFRelease(result)
                self.cf.CFRelease(query)
        return items

    def delete(self, item):
        reference = item['reference']
        if not reference or item['kind'] not in ('kSecClassGenericPassword', 'kSecClassInternetPassword'):
            raise ValueError('Missing exact Keychain identity')
        data = self.cf.CFDataCreate(None, reference, len(reference))
        array = self.cf.CFArrayCreate(None, (C.c_void_p * 1)(data), 1,
                                      self.callbacks('kCFTypeArrayCallBacks'))
        query = self.dictionary([('kSecClass', self.constant(item['kind'])),
                                 ('kSecMatchItemList', array)])
        try:
            status = self.sec.SecItemDelete(query)
            if status not in (0, -25300):
                raise KeychainError('Keychain deletion', status)
        finally:
            self.cf.CFRelease(query)
            self.cf.CFRelease(array)
            self.cf.CFRelease(data)
