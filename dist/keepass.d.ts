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
        streamKey: any;
        private getKey(h, masterPassword, fileKey);
        getPasswords(buf: any, masterPassword: any, keyFile: any): Promise<any>;
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
    class Util {
        static littleEndian: boolean;
        static convertArrayToUUID(arr: any): string;
        static str2ab(binaryString: String): ArrayBuffer;
    }
}
