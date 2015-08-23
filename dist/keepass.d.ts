/// <reference path="../keepass.js/node_modules/typescript/bin/lib.es6.d.ts" />
/// <reference path="../keepass.js/typings/tsd.d.ts" />
declare module Keepass {
    class HeaderParser {
        private AES_CIPHER_UUID;
        readHeader(buf: any): any;
        private readKdbHeader(buf, position, h);
        private readKdbxHeader(buf, position, h);
    }
}
declare var Salsa20: any;
declare module Keepass {
    class KdbParser {
        parse(buf: any, streamKey: any, h: any): any[];
        private readEntryField(fieldType, fieldSize, buf, pos, entry);
        private readGroupField(fieldType, fieldSize, buf, pos, group);
    }
}
declare var pako: any, Salsa20: any, Case: any;
declare module Keepass {
    class Database {
        private headerParser;
        private masterKeyUtil;
        streamKey: any;
        getPasswords(buf: any, masterPassword: any, keyFile?: any): any;
        private decryptStreamKey(protectedStreamKey);
        /**
         * Returns the decrypted data from a protected element of a KDBX entry
         */
        decryptProtectedData(protectedData: any, streamKey: any): string;
        /**
         * Parses the KDBX entries xml into an object format
         **/
        private parseXml(xml);
        private aes_ecb_encrypt(rawKey, data, rounds);
        private aes_cbc_rounds(data, rawKey, rounds);
        private aes_cbc_rounds_single(data, rawKey, rounds);
    }
}
declare module Keepass {
    /**
    * Parses a KeePass key file
    */
    class KeyFileParser {
        getKeyFromFile(arr: any): any;
    }
}
declare module Keepass {
    /**
     * Utility for inferring the master key from the master password and
     * additionally from a keyfile
     */
    class MasterKeyUtil {
        private keyFileParser;
        inferMasterKey(h: any, masterPassword: any, keyFile?: any): any;
        private infer(h, masterPassword, fileKey?);
    }
}
declare module Keepass {
    class Util {
        static littleEndian: boolean;
        static convertArrayToUUID(arr: any): string;
        /**
         * Converts the given ArrayBuffer to a binary string
         */
        static ab2str(arr: any): String;
        /**
         * Converts the given binaryString to an ArrayBuffer
         */
        static str2ab(binaryString: String): ArrayBuffer;
        static hex2arr(hex: string): any[];
    }
}
