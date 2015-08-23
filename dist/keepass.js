/// <reference path="../node_modules/typescript/bin/lib.es6.d.ts" />
var Keepass;
(function (Keepass) {
    var HeaderParser = (function () {
        function HeaderParser() {
            this.AES_CIPHER_UUID = new Uint8Array([0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff]);
        }
        HeaderParser.prototype.readHeader = function (buf) {
            var sigHeader = new DataView(buf, 0, 8);
            var h = {
                sigKeePass: sigHeader.getUint32(0, Keepass.Util.littleEndian),
                sigKeePassType: sigHeader.getUint32(4, Keepass.Util.littleEndian)
            };
            var DBSIG_KEEPASS = 0x9AA2D903;
            var DBSIG_KDBX = 0xB54BFB67, DBSIG_KDBX_ALPHA = 0xB54BFB66, DBSIG_KDB = 0xB54BFB55, DBSIG_KDB_NEW = 0xB54BFB65;
            var VERSION_KDBX = 3;
            if (h.sigKeePass != DBSIG_KEEPASS || (h.sigKeePassType != DBSIG_KDBX && h.sigKeePassType != DBSIG_KDBX_ALPHA && h.sigKeePassType != DBSIG_KDB && h.sigKeePassType != DBSIG_KDB_NEW)) {
                //fail
                console.log("Signature fail.  sig 1:" + h.sigKeePass.toString(16) + ", sig2:" + h.sigKeePassType.toString(16));
                throw new Error('This is not a valid KeePass file - file signature is not correct.');
            }
            if (h.sigKeePassType == DBSIG_KDBX || h.sigKeePassType == DBSIG_KDBX_ALPHA) {
                this.readKdbxHeader(buf, 8, h);
            }
            else {
                this.readKdbHeader(buf, 8, h);
            }
            //console.log(h);
            //console.log("version: " + h.version.toString(16) + ", keyRounds: " + h.keyRounds);
            return h;
        };
        HeaderParser.prototype.readKdbHeader = function (buf, position, h) {
            var FLAG_SHA2 = 1;
            var FLAG_RIJNDAEL = 2;
            var FLAG_ARCFOUR = 4;
            var FLAG_TWOFISH = 8;
            var dv = new DataView(buf, position, 116);
            var flags = dv.getUint32(0, Keepass.Util.littleEndian);
            if ((flags & FLAG_RIJNDAEL) != FLAG_RIJNDAEL) {
                throw new Error('We only support AES (aka Rijndael) encryption on KeePass KDB files.  This file is using something else.');
            }
            try {
                h.cipher = this.AES_CIPHER_UUID;
                h.majorVersion = dv.getUint16(4, Keepass.Util.littleEndian);
                h.minorVersion = dv.getUint16(6, Keepass.Util.littleEndian);
                h.masterSeed = new Uint8Array(buf, position + 8, 16);
                h.iv = new Uint8Array(buf, position + 24, 16);
                h.numberOfGroups = dv.getUint32(40, Keepass.Util.littleEndian);
                h.numberOfEntries = dv.getUint32(44, Keepass.Util.littleEndian);
                h.contentsHash = new Uint8Array(buf, position + 48, 32);
                h.transformSeed = new Uint8Array(buf, position + 80, 32);
                h.keyRounds = dv.getUint32(112, Keepass.Util.littleEndian);
                //constants for KDB:
                h.keyRounds2 = 0;
                h.compressionFlags = 0;
                h.protectedStreamKey = window.crypto.getRandomValues(new Uint8Array(16)); //KDB does not have this, but we will create in order to protect the passwords
                h.innerRandomStreamId = 0;
                h.streamStartBytes = null;
                h.kdb = true;
                h.dataStart = position + 116; //=124 - the size of the KDB header
            }
            catch (err) {
                throw new Error('Failed to parse KDB file header - file is corrupt or format not supported');
            }
        };
        HeaderParser.prototype.readKdbxHeader = function (buf, position, h) {
            try {
                var version = new DataView(buf, position, 4);
                h.majorVersion = version.getUint16(0, Keepass.Util.littleEndian);
                h.minorVersion = version.getUint16(2, Keepass.Util.littleEndian);
                position += 4;
                var done = false;
                while (!done) {
                    var descriptor = new DataView(buf, position, 3);
                    var fieldId = descriptor.getUint8(0);
                    var len = descriptor.getUint16(1, Keepass.Util.littleEndian);
                    var dv = new DataView(buf, position + 3, len);
                    //console.log("fieldid " + fieldId + " found at " + position);
                    position += 3;
                    switch (fieldId) {
                        case 0:
                            done = true;
                            break;
                        case 2:
                            h.cipher = new Uint8Array(buf, position, len);
                            break;
                        case 3:
                            h.compressionFlags = dv.getUint32(0, Keepass.Util.littleEndian);
                            break;
                        case 4:
                            h.masterSeed = new Uint8Array(buf, position, len);
                            break;
                        case 5:
                            h.transformSeed = new Uint8Array(buf, position, len);
                            break;
                        case 6:
                            h.keyRounds = dv.getUint32(0, Keepass.Util.littleEndian);
                            h.keyRounds2 = dv.getUint32(4, Keepass.Util.littleEndian);
                            break;
                        case 7:
                            h.iv = new Uint8Array(buf, position, len);
                            break;
                        case 8:
                            h.protectedStreamKey = new Uint8Array(buf, position, len);
                            break;
                        case 9:
                            h.streamStartBytes = new Uint8Array(buf, position, len);
                            break;
                        case 10:
                            h.innerRandomStreamId = dv.getUint32(0, Keepass.Util.littleEndian);
                            break;
                        default:
                            break;
                    }
                    position += len;
                }
                h.kdbx = true;
                h.dataStart = position;
            }
            catch (err) {
                throw new Error('Failed to parse KDBX file header - file is corrupt or format not supported');
            }
        };
        return HeaderParser;
    })();
    Keepass.HeaderParser = HeaderParser;
})(Keepass || (Keepass = {}));
/// <reference path="../typings/tsd.d.ts" />
var Keepass;
(function (Keepass) {
    var KdbParser = (function () {
        function KdbParser() {
        }
        KdbParser.prototype.parse = function (buf, streamKey, h) {
            var iv = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
            var salsa = new Salsa20(new Uint8Array(streamKey), iv);
            var salsaPosition = 0;
            var pos = 0;
            var dv = new DataView(buf);
            var groups = [];
            for (var i = 0; i < h.numberOfGroups; i++) {
                var fieldType = 0, fieldSize = 0;
                var currentGroup = {};
                var preventInfinite = 100;
                while (fieldType != 0xFFFF && preventInfinite > 0) {
                    fieldType = dv.getUint16(pos, Keepass.Util.littleEndian);
                    fieldSize = dv.getUint32(pos + 2, Keepass.Util.littleEndian);
                    pos += 6;
                    this.readGroupField(fieldType, fieldSize, buf, pos, currentGroup);
                    pos += fieldSize;
                    preventInfinite -= 1;
                }
                groups.push(currentGroup);
            }
            var entries = [];
            for (var i = 0; i < h.numberOfEntries; i++) {
                var fieldType = 0, fieldSize = 0;
                var currentEntry = { keys: [] };
                var preventInfinite = 100;
                while (fieldType != 0xFFFF && preventInfinite > 0) {
                    fieldType = dv.getUint16(pos, Keepass.Util.littleEndian);
                    fieldSize = dv.getUint32(pos + 2, Keepass.Util.littleEndian);
                    pos += 6;
                    this.readEntryField(fieldType, fieldSize, buf, pos, currentEntry);
                    pos += fieldSize;
                    preventInfinite -= 1;
                }
                //if (Case.constant(currentEntry.title) != "META_INFO") {
                //meta-info items are not actual password entries
                currentEntry.group = groups.filter(function (grp) {
                    return grp.id == currentEntry.groupId;
                })[0];
                currentEntry.groupName = currentEntry.group.name;
                //in-memory-protect the password in the same way as on KDBX
                if (currentEntry.password) {
                    var encoder = new TextEncoder();
                    var passwordBytes = encoder.encode(currentEntry.password);
                    var encPassword = salsa.encrypt(new Uint8Array(passwordBytes));
                    currentEntry.protectedData = {
                        password: {
                            data: encPassword,
                            position: salsaPosition
                        }
                    };
                    currentEntry.password = btoa(encPassword); //not used - just for consistency with KDBX
                    salsaPosition += passwordBytes.byteLength;
                }
                if (!(currentEntry.title == 'Meta-Info' && currentEntry.userName == 'SYSTEM')
                    && (currentEntry.groupName != 'Backup')
                    && (currentEntry.groupName != 'Search Results'))
                    entries.push(currentEntry);
            }
            return entries;
        };
        //read KDB entry field
        KdbParser.prototype.readEntryField = function (fieldType, fieldSize, buf, pos, entry) {
            var dv = new DataView(buf, pos, fieldSize);
            var arr = new Uint8Array(0);
            if (fieldSize > 0) {
                arr = new Uint8Array(buf, pos, fieldSize - 1);
            }
            var decoder = new TextDecoder();
            switch (fieldType) {
                case 0x0000:
                    // Ignore field
                    break;
                case 0x0001:
                    entry.id = Keepass.Util.convertArrayToUUID(new Uint8Array(buf, pos, fieldSize));
                    break;
                case 0x0002:
                    entry.groupId = dv.getUint32(0, Keepass.Util.littleEndian);
                    break;
                case 0x0003:
                    entry.iconId = dv.getUint32(0, Keepass.Util.littleEndian);
                    break;
                case 0x0004:
                    entry.title = decoder.decode(arr);
                    entry.keys.push('title');
                    break;
                case 0x0005:
                    entry.url = decoder.decode(arr);
                    entry.keys.push('url');
                    break;
                case 0x0006:
                    entry.userName = decoder.decode(arr);
                    entry.keys.push('userName');
                    break;
                case 0x0007:
                    entry.password = decoder.decode(arr);
                    break;
                case 0x0008:
                    entry.notes = decoder.decode(arr);
                    entry.keys.push('notes');
                    break;
            }
        };
        KdbParser.prototype.readGroupField = function (fieldType, fieldSize, buf, pos, group) {
            var dv = new DataView(buf, pos, fieldSize);
            var arr = new Uint8Array(0);
            if (fieldSize > 0) {
                arr = new Uint8Array(buf, pos, fieldSize - 1);
            }
            switch (fieldType) {
                case 0x0000:
                    // Ignore field
                    break;
                case 0x0001:
                    group.id = dv.getUint32(0, Keepass.Util.littleEndian);
                    break;
                case 0x0002:
                    var decoder = new TextDecoder();
                    group.name = decoder.decode(arr);
                    break;
            }
        };
        return KdbParser;
    })();
    Keepass.KdbParser = KdbParser;
})(Keepass || (Keepass = {}));
/// <reference path="../typings/tsd.d.ts" />
var Keepass;
(function (Keepass) {
    var Database = (function () {
        function Database() {
            this.headerParser = new Keepass.HeaderParser();
            this.masterKeyUtil = new Keepass.MasterKeyUtil();
        }
        Database.prototype.getPasswords = function (buf, masterPassword, keyFile) {
            var _this = this;
            var h = this.headerParser.readHeader(buf);
            if (!h)
                throw new Error('Failed to read file header');
            if (h.innerRandomStreamId != 2 && h.innerRandomStreamId != 0)
                throw new Error('Invalid Stream Key - Salsa20 is supported by this implementation, Arc4 and others not implemented.');
            var encData = new Uint8Array(buf, h.dataStart);
            //console.log("read file header ok.  encrypted data starts at byte " + h.dataStart);
            var SHA = {
                name: "SHA-256"
            };
            var AES = {
                name: "AES-CBC",
                iv: h.iv
            };
            return this.masterKeyUtil.inferMasterKey(h, masterPassword, keyFile).then(function (masterKey) {
                //transform master key thousands of times
                return _this.aes_ecb_encrypt(h.transformSeed, masterKey, h.keyRounds);
            }).then(function (finalVal) {
                //do a final SHA-256 on the transformed key
                return window.crypto.subtle.digest({
                    name: "SHA-256"
                }, finalVal);
            }).then(function (encMasterKey) {
                var finalKeySource = new Uint8Array(h.masterSeed.byteLength + 32);
                finalKeySource.set(h.masterSeed);
                finalKeySource.set(new Uint8Array(encMasterKey), h.masterSeed.byteLength);
                return window.crypto.subtle.digest(SHA, finalKeySource);
            }).then(function (finalKeyBeforeImport) {
                return window.crypto.subtle.importKey("raw", finalKeyBeforeImport, AES, false, ["decrypt"]);
            }).then(function (finalKey) {
                return window.crypto.subtle.decrypt(AES, finalKey, encData);
            }).then(function (decryptedData) {
                //at this point we probably have successfully decrypted data, just need to double-check:
                if (h.kdbx) {
                    //kdbx
                    var storedStartBytes = new Uint8Array(decryptedData, 0, 32);
                    for (var i = 0; i < 32; i++) {
                        if (storedStartBytes[i] != h.streamStartBytes[i]) {
                            throw new Error('Decryption succeeded but payload corrupt');
                            return;
                        }
                    }
                    //ok, data decrypted, lets start parsing:
                    var done = false, pos = 32;
                    var blockArray = [], totalDataLength = 0;
                    while (!done) {
                        var blockHeader = new DataView(decryptedData, pos, 40);
                        var blockId = blockHeader.getUint32(0, Keepass.Util.littleEndian);
                        var blockSize = blockHeader.getUint32(36, Keepass.Util.littleEndian);
                        var blockHash = new Uint8Array(decryptedData, pos + 4, 32);
                        if (blockSize > 0) {
                            var block = new Uint8Array(decryptedData, pos + 40, blockSize);
                            blockArray.push(block);
                            totalDataLength += blockSize;
                            pos += blockSize + 40;
                        }
                        else {
                            //final block is a zero block
                            done = true;
                        }
                    }
                    var allBlocks = new Uint8Array(totalDataLength);
                    pos = 0;
                    for (var i = 0; i < blockArray.length; i++) {
                        allBlocks.set(blockArray[i], pos);
                        pos += blockArray[i].byteLength;
                    }
                    if (h.compressionFlags == 1) {
                        allBlocks = pako.inflate(allBlocks);
                    }
                    var decoder = new TextDecoder();
                    var xml = decoder.decode(allBlocks);
                    return _this.decryptStreamKey(h.protectedStreamKey).then(function (streamKey) {
                        var entries = _this.parseXml(xml);
                        return entries;
                    });
                }
                else {
                    return _this.decryptStreamKey(h.protectedStreamKey).then(function (streamKey) {
                        //kdb
                        var entries = new Keepass.KdbParser().parse(decryptedData, streamKey, h);
                        return entries;
                    });
                }
            });
        };
        Database.prototype.decryptStreamKey = function (protectedStreamKey) {
            var _this = this;
            return window.crypto.subtle.digest({
                name: "SHA-256"
            }, protectedStreamKey).then(function (streamKey) {
                _this.streamKey = streamKey;
                return streamKey;
            });
        };
        /**
         * Returns the decrypted data from a protected element of a KDBX entry
         */
        Database.prototype.decryptProtectedData = function (protectedData, streamKey) {
            if (protectedData === undefined)
                return ""; //can happen with entries with no password
            var iv = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
            var salsa = new Salsa20(new Uint8Array(streamKey || this.streamKey), iv);
            var decoder = new TextDecoder();
            salsa.getBytes(protectedData.position);
            var decryptedBytes = new Uint8Array(salsa.decrypt(protectedData.data));
            return decoder.decode(decryptedBytes);
        };
        /**
         * Parses the KDBX entries xml into an object format
         **/
        Database.prototype.parseXml = function (xml) {
            var decoder = new TextDecoder();
            var parser = new DOMParser();
            var doc = parser.parseFromString(xml, "text/xml");
            //console.log(doc);
            var results = [];
            var entryNodes = doc.evaluate('//Entry', doc, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
            var protectedPosition = 0;
            for (var i = 0; i < entryNodes.snapshotLength; i++) {
                var entryNode = entryNodes.snapshotItem(i);
                //console.log(entryNode);
                var entry = {
                    protectedData: {},
                    keys: []
                };
                //exclude histories and recycle bin:
                if (entryNode.parentNode.nodeName != "History") {
                    for (var m = 0; m < entryNode.parentNode.children.length; m++) {
                        var groupNode = entryNode.parentNode.children[m];
                        if (groupNode.nodeName == 'Name')
                            entry.groupName = groupNode.textContent;
                    }
                    if (entry.groupName != "Recycle Bin")
                        results.push(entry);
                }
                for (var j = 0; j < entryNode.children.length; j++) {
                    var childNode = entryNode.children[j];
                    if (childNode.nodeName == "UUID") {
                        entry.id = Keepass.Util.convertArrayToUUID(Keepass.Util.str2ab(atob(childNode.textContent)));
                    }
                    else if (childNode.nodeName == "IconID") {
                        entry.iconId = Number(childNode.textContent); //integer
                    }
                    else if (childNode.nodeName == "Tags" && childNode.textContent) {
                        entry.tags = childNode.textContent;
                        entry.keys.push('tags');
                    }
                    else if (childNode.nodeName == "Binary") {
                        entry.binaryFiles = childNode.textContent;
                        entry.keys.push('binaryFiles'); //the actual files are stored elsewhere in the xml, not sure where
                    }
                    else if (childNode.nodeName == "String") {
                        var key = childNode.getElementsByTagName('Key')[0].textContent;
                        key = Case.camel(key);
                        var valNode = childNode.getElementsByTagName('Value')[0];
                        var val = valNode.textContent;
                        var protectedVal = valNode.hasAttribute('Protected');
                        if (protectedVal) {
                            var encBytes = new Uint8Array(Keepass.Util.str2ab(atob(val)));
                            entry.protectedData[key] = {
                                position: protectedPosition,
                                data: encBytes
                            };
                            protectedPosition += encBytes.length;
                        }
                        else {
                            entry.keys.push(key);
                        }
                        entry[key] = val;
                    }
                }
            }
            //console.log(results);
            return results;
        };
        Database.prototype.aes_ecb_encrypt = function (rawKey, data, rounds) {
            var _this = this;
            data = new Uint8Array(data);
            //Simulate ECB encryption by using IV of the data.
            var blockCount = data.byteLength / 16;
            var blockPromises = new Array(blockCount);
            for (var i = 0; i < blockCount; i++) {
                var block = data.subarray(i * 16, i * 16 + 16);
                blockPromises[i] = (function (iv) {
                    return _this.aes_cbc_rounds(iv, rawKey, rounds);
                })(block);
            }
            return Promise.all(blockPromises).then(function (blocks) {
                //we now have the blocks, so chain them back together
                var result = new Uint8Array(data.byteLength);
                for (var i = 0; i < blockCount; i++) {
                    result.set(blocks[i], i * 16);
                }
                return result;
            });
        };
        /*
        * Performs rounds of CBC encryption on data using rawKey
        */
        Database.prototype.aes_cbc_rounds = function (data, rawKey, rounds) {
            var _this = this;
            if (rounds == 0) {
                //just pass back the current value
                return data;
            }
            else if (rounds > 0xFFFF) {
                //limit memory use to avoid chrome crash:
                return this.aes_cbc_rounds_single(data, rawKey, 0xFFFF).then(function (result) {
                    return _this.aes_cbc_rounds(result, rawKey, rounds - 0xFFFF);
                });
            }
            else {
                //last iteration, or only iteration if original rounds was low:
                return this.aes_cbc_rounds_single(data, rawKey, rounds);
            }
        };
        Database.prototype.aes_cbc_rounds_single = function (data, rawKey, rounds) {
            var AES = {
                name: "AES-CBC",
                iv: data
            };
            return window.crypto.subtle.importKey("raw", rawKey, AES, false, ["encrypt"]).then(function (secureKey) {
                var fakeData = new Uint8Array(rounds * 16);
                return window.crypto.subtle.encrypt(AES, secureKey, fakeData);
            }).then(function (result) {
                return new Uint8Array(result, (rounds - 1) * 16, 16);
            });
        };
        return Database;
    })();
    Keepass.Database = Database;
})(Keepass || (Keepass = {}));
/// <reference path="../typings/tsd.d.ts" />
var Keepass;
(function (Keepass) {
    /**
    * Parses a KeePass key file
    */
    var KeyFileParser = (function () {
        function KeyFileParser() {
        }
        KeyFileParser.prototype.getKeyFromFile = function (arr) {
            if (arr.byteLength == 0) {
                return Promise.reject(new Error('key file has zero bytes'));
            }
            else if (arr.byteLength == 32) {
                //file content is the key
                return Promise.resolve(arr);
            }
            else if (arr.byteLength == 64) {
                //file content may be a hex string of the key
                var decoder = new TextDecoder();
                var hexString = decoder.decode(arr);
                var newArr = Keepass.Util.hex2arr(hexString);
                if (newArr.length == 32) {
                    return Promise.resolve(newArr);
                }
            }
            //attempt to parse xml
            try {
                var decoder = new TextDecoder();
                var xml = decoder.decode(arr);
                var parser = new DOMParser();
                var doc = parser.parseFromString(xml, "text/xml");
                var keyNode = doc.evaluate('//KeyFile/Key/Data', doc, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
                if (keyNode.singleNodeValue && keyNode.singleNodeValue.textContent) {
                    return Promise.resolve(Keepass.Util.str2ab(atob(keyNode.singleNodeValue.textContent)));
                }
            }
            catch (err) {
            }
            // finally just create a sha256 hash from the file contents
            return window.crypto.subtle.digest({ name: "SHA-256" }, arr);
        };
        return KeyFileParser;
    })();
    Keepass.KeyFileParser = KeyFileParser;
})(Keepass || (Keepass = {}));
/// <reference path="../typings/tsd.d.ts" />
var Keepass;
(function (Keepass) {
    /**
     * Utility for inferring the master key from the master password and
     * additionally from a keyfile
     */
    var MasterKeyUtil = (function () {
        function MasterKeyUtil() {
            this.keyFileParser = new Keepass.KeyFileParser();
        }
        MasterKeyUtil.prototype.inferMasterKey = function (h, masterPassword, keyFile) {
            var _this = this;
            if (keyFile) {
                return this.keyFileParser.getKeyFromFile(keyFile).then(function (key) {
                    return _this.infer(h, masterPassword, key);
                });
            }
            else {
                return this.infer(h, masterPassword);
            }
        };
        MasterKeyUtil.prototype.infer = function (h, masterPassword, fileKey) {
            var partPromises = [];
            var SHA = {
                name: "SHA-256"
            };
            if (masterPassword || !fileKey) {
                var encoder = new TextEncoder();
                var masterKey = encoder.encode(masterPassword);
                var p = window.crypto.subtle.digest(SHA, new Uint8Array(masterKey));
                partPromises.push(p);
            }
            if (fileKey) {
                partPromises.push(Promise.resolve(fileKey));
            }
            return Promise.all(partPromises).then(function (parts) {
                if (h.kdbx || partPromises.length > 1) {
                    //kdbx, or kdb with fileKey + masterPassword, do the SHA a second time
                    var compositeKeySource = new Uint8Array(32 * parts.length);
                    for (var i = 0; i < parts.length; i++) {
                        compositeKeySource.set(new Uint8Array(parts[i]), i * 32);
                    }
                    return window.crypto.subtle.digest(SHA, compositeKeySource);
                }
                else {
                    //kdb with just only fileKey or masterPassword (don't do a second SHA digest in this scenario)
                    return partPromises[0];
                }
            });
        };
        return MasterKeyUtil;
    })();
    Keepass.MasterKeyUtil = MasterKeyUtil;
})(Keepass || (Keepass = {}));
var Keepass;
(function (Keepass) {
    var Util = (function () {
        function Util() {
        }
        Util.convertArrayToUUID = function (arr) {
            var int8Arr = new Uint8Array(arr);
            var result = new Array(int8Arr.byteLength * 2);
            for (var i = 0; i < int8Arr.byteLength; i++) {
                result[i * 2] = int8Arr[i].toString(16).toUpperCase();
            }
            return result.join("");
        };
        /**
         * Converts the given ArrayBuffer to a binary string
         */
        Util.ab2str = function (arr) {
            var binary = '';
            var bytes = new Uint8Array(arr);
            for (var i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return binary;
        };
        /**
         * Converts the given binaryString to an ArrayBuffer
         */
        Util.str2ab = function (binaryString) {
            var len = binaryString.length;
            var bytes = new Uint8Array(len);
            for (var i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        };
        Util.hex2arr = function (hex) {
            if (hex.length % 2 != 0 || !/^[0-9A-Fa-f]+$/.test(hex)) {
                return [];
            }
            var arr = [];
            for (var i = 0; i < hex.length; i += 2)
                arr.push(parseInt(hex.substr(i, 2), 16));
            return arr;
        };
        Util.littleEndian = (function () {
            var buffer = new ArrayBuffer(2);
            new DataView(buffer).setInt16(0, 256, true);
            return new Int16Array(buffer)[0] === 256;
        })();
        return Util;
    })();
    Keepass.Util = Util;
})(Keepass || (Keepass = {}));
