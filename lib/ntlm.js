'use strict';

/* eslint-disable no-bitwise */
const crypto = require('crypto');

const flags = {
  NTLM_NegotiateUnicode: 0x00000001,
  NTLM_NegotiateOEM: 0x00000002,
  NTLM_RequestTarget: 0x00000004,
  NTLM_Unknown9: 0x00000008,
  NTLM_NegotiateSign: 0x00000010,
  NTLM_NegotiateSeal: 0x00000020,
  NTLM_NegotiateDatagram: 0x00000040,
  NTLM_NegotiateLanManagerKey: 0x00000080,
  NTLM_Unknown8: 0x00000100,
  NTLM_NegotiateNTLM: 0x00000200,
  NTLM_NegotiateNTOnly: 0x00000400,
  NTLM_Anonymous: 0x00000800,
  NTLM_NegotiateOemDomainSupplied: 0x00001000,
  NTLM_NegotiateOemWorkstationSupplied: 0x00002000,
  NTLM_Unknown6: 0x00004000,
  NTLM_NegotiateAlwaysSign: 0x00008000,
  NTLM_TargetTypeDomain: 0x00010000,
  NTLM_TargetTypeServer: 0x00020000,
  NTLM_TargetTypeShare: 0x00040000,
  NTLM_NegotiateExtendedSecurity: 0x00080000,
  NTLM_NegotiateIdentify: 0x00100000,
  NTLM_Unknown5: 0x00200000,
  NTLM_RequestNonNTSessionKey: 0x00400000,
  NTLM_NegotiateTargetInfo: 0x00800000,
  NTLM_Unknown4: 0x01000000,
  NTLM_NegotiateVersion: 0x02000000,
  NTLM_Unknown3: 0x04000000,
  NTLM_Unknown2: 0x08000000,
  NTLM_Unknown1: 0x10000000,
  NTLM_Negotiate128: 0x20000000,
  NTLM_NegotiateKeyExchange: 0x40000000,
  NTLM_Negotiate56: 0x80000000,
};
const typeflags = {
  NTLM_TYPE1_FLAGS: flags.NTLM_NegotiateUnicode
            + flags.NTLM_NegotiateOEM
            + flags.NTLM_RequestTarget
            + flags.NTLM_NegotiateNTLM
            + flags.NTLM_NegotiateOemDomainSupplied
            + flags.NTLM_NegotiateOemWorkstationSupplied
            + flags.NTLM_NegotiateAlwaysSign
            + flags.NTLM_NegotiateExtendedSecurity
            + flags.NTLM_NegotiateVersion
            + flags.NTLM_Negotiate128
            + flags.NTLM_Negotiate56,

  NTLM_TYPE2_FLAGS: flags.NTLM_NegotiateUnicode
            + flags.NTLM_RequestTarget
            + flags.NTLM_NegotiateNTLM
            + flags.NTLM_NegotiateAlwaysSign
            + flags.NTLM_NegotiateExtendedSecurity
            + flags.NTLM_NegotiateTargetInfo
            + flags.NTLM_NegotiateVersion
            + flags.NTLM_Negotiate128
            + flags.NTLM_Negotiate56,
};

function createType1Message(options) {
  const domain = escape(options.ntlm_domain.toUpperCase());
  const workstation = escape(options.workstation.toUpperCase());
  const protocol = 'NTLMSSP\0';

  const BODY_LENGTH = 40;

  let type1flags = typeflags.NTLM_TYPE1_FLAGS;
  if (!domain || domain === '')
  { type1flags -= flags.NTLM_NegotiateOemDomainSupplied; }

  let pos = 0;
  const buf = Buffer.alloc(BODY_LENGTH + domain.length + workstation.length);


  buf.write(protocol, pos, protocol.length); pos += protocol.length; // protocol
  buf.writeUInt32LE(1, pos); pos += 4;          // type 1
  buf.writeUInt32LE(type1flags, pos); pos += 4; // TYPE1 flag

  buf.writeUInt16LE(domain.length, pos); pos += 2; // domain length
  buf.writeUInt16LE(domain.length, pos); pos += 2; // domain max length
  buf.writeUInt32LE(BODY_LENGTH + workstation.length, pos); pos += 4; // domain buffer offset

  buf.writeUInt16LE(workstation.length, pos); pos += 2; // workstation length
  buf.writeUInt16LE(workstation.length, pos); pos += 2; // workstation max length
  buf.writeUInt32LE(BODY_LENGTH, pos); pos += 4; // workstation buffer offset

  buf.writeUInt8(5, pos); pos += 1;      // ProductMajorVersion
  buf.writeUInt8(1, pos); pos += 1;      // ProductMinorVersion
  buf.writeUInt16LE(2600, pos); pos += 2; // ProductBuild

  buf.writeUInt8(0, pos); pos += 1; // VersionReserved1
  buf.writeUInt8(0, pos); pos += 1; // VersionReserved2
  buf.writeUInt8(0, pos); pos += 1; // VersionReserved3
  buf.writeUInt8(15, pos); pos += 1; // NTLMRevisionCurrent

  buf.write(workstation, pos, workstation.length, 'ascii'); pos += workstation.length; // workstation string
  buf.write(domain, pos, domain.length, 'ascii'); pos += domain.length;

  return `NTLM ${buf.toString('base64')}`;
}

function parseType2Message(rawmsg, callback) {
  const match = rawmsg.match(/NTLM (.+)?/);
  if (!match || !match[1])
  { return callback(new Error("Couldn't find NTLM in the message type2 comming from the server")); }

  const buf = Buffer.from(match[1], 'base64');

  const msg = {};

  msg.signature = buf.slice(0, 8);
  msg.type = buf.readInt16LE(8);

  if (msg.type !== 2)
  { return callback(new Error("Server didn't return a type 2 message")); }

  msg.targetNameLen = buf.readInt16LE(12);
  msg.targetNameMaxLen = buf.readInt16LE(14);
  msg.targetNameOffset = buf.readInt32LE(16);
  msg.targetName  = buf.slice(msg.targetNameOffset, msg.targetNameOffset + msg.targetNameMaxLen);

  msg.negotiateFlags = buf.readInt32LE(20);
  msg.serverChallenge = buf.slice(24, 32);
  msg.reserved = buf.slice(32, 40);

  if (msg.negotiateFlags & flags.NTLM_NegotiateTargetInfo) {
    msg.targetInfoLen = buf.readInt16LE(40);
    msg.targetInfoMaxLen = buf.readInt16LE(42);
    msg.targetInfoOffset = buf.readInt32LE(44);
    msg.targetInfo = buf.slice(msg.targetInfoOffset, msg.targetInfoOffset + msg.targetInfoLen);
  }
  return msg;
}

function createType3Message(msg2, options) {
  const nonce = msg2.serverChallenge;
  const username = options.username;
  const password = options.password;
  const negotiateFlags = msg2.negotiateFlags;

  const isUnicode = negotiateFlags & flags.NTLM_NegotiateUnicode;
  const isNegotiateExtendedSecurity = negotiateFlags & flags.NTLM_NegotiateExtendedSecurity;

  const BODY_LENGTH = 72;

  const domainName = escape(options.ntlm_domain.toUpperCase());
  const workstation = escape(options.workstation.toUpperCase());

  let workstationBytes,
    domainNameBytes,
    usernameBytes,
    encryptedRandomSessionKeyBytes;

  const encryptedRandomSessionKey = '';
  if (isUnicode) {
    workstationBytes = Buffer.from(workstation, 'utf16le');
    domainNameBytes = Buffer.from(domainName, 'utf16le');
    usernameBytes = Buffer.from(username, 'utf16le');
    encryptedRandomSessionKeyBytes = Buffer.from(encryptedRandomSessionKey, 'utf16le');
  } else {
    workstationBytes = Buffer.from(workstation, 'ascii');
    domainNameBytes = Buffer.from(domainName, 'ascii');
    usernameBytes = Buffer.from(username, 'ascii');
    encryptedRandomSessionKeyBytes = Buffer.from(encryptedRandomSessionKey, 'ascii');
  }

  let lmChallengeResponse = calcResp(createLMHashedPasswordV1(password), nonce);
  let ntChallengeResponse = calcResp(createNTHashedPasswordV1(password), nonce);

  if (isNegotiateExtendedSecurity) {
    const pwhash = createNTHashedPasswordV1(password);
    let clientChallenge = '';
    for (let i = 0; i < 8; i++) {
      clientChallenge += String.fromCharCode(Math.floor(Math.random() * 256));
    }
    const clientChallengeBytes = Buffer.from(clientChallenge, 'ascii');
    const challenges = ntlm2srCalcResp(pwhash, nonce, clientChallengeBytes);
    lmChallengeResponse = challenges.lmChallengeResponse;
    ntChallengeResponse = challenges.ntChallengeResponse;
  }

  const signature = 'NTLMSSP\0';

  let pos = 0;
  const buf = Buffer.alloc(BODY_LENGTH + domainNameBytes.length + usernameBytes.length +
    workstationBytes.length + lmChallengeResponse.length + ntChallengeResponse.length + encryptedRandomSessionKeyBytes.length);

  buf.write(signature, pos, signature.length); pos += signature.length;
  buf.writeUInt32LE(3, pos); pos += 4;          // type 1

  buf.writeUInt16LE(lmChallengeResponse.length, pos); pos += 2; // LmChallengeResponseLen
  buf.writeUInt16LE(lmChallengeResponse.length, pos); pos += 2; // LmChallengeResponseMaxLen
  buf.writeUInt32LE(BODY_LENGTH + domainNameBytes.length + usernameBytes.length +
    workstationBytes.length, pos); pos += 4; // LmChallengeResponseOffset

  buf.writeUInt16LE(ntChallengeResponse.length, pos); pos += 2; // NtChallengeResponseLen
  buf.writeUInt16LE(ntChallengeResponse.length, pos); pos += 2; // NtChallengeResponseMaxLen
  buf.writeUInt32LE(BODY_LENGTH + domainNameBytes.length + usernameBytes.length +
  workstationBytes.length + lmChallengeResponse.length, pos);
  pos += 4; // NtChallengeResponseOffset

  buf.writeUInt16LE(domainNameBytes.length, pos); pos += 2; // DomainNameLen
  buf.writeUInt16LE(domainNameBytes.length, pos); pos += 2; // DomainNameMaxLen
  buf.writeUInt32LE(BODY_LENGTH, pos); pos += 4;        // DomainNameOffset

  buf.writeUInt16LE(usernameBytes.length, pos); pos += 2; // UserNameLen
  buf.writeUInt16LE(usernameBytes.length, pos); pos += 2; // UserNameMaxLen
  buf.writeUInt32LE(BODY_LENGTH + domainNameBytes.length, pos); pos += 4; // UserNameOffset

  buf.writeUInt16LE(workstationBytes.length, pos); pos += 2; // WorkstationLen
  buf.writeUInt16LE(workstationBytes.length, pos); pos += 2; // WorkstationMaxLen
  buf.writeUInt32LE(BODY_LENGTH + domainNameBytes.length + usernameBytes.length, pos); pos += 4; // WorkstationOffset

  buf.writeUInt16LE(encryptedRandomSessionKeyBytes.length, pos); pos += 2; // EncryptedRandomSessionKeyLen
  buf.writeUInt16LE(encryptedRandomSessionKeyBytes.length, pos); pos += 2; // EncryptedRandomSessionKeyMaxLen
  buf.writeUInt32LE(BODY_LENGTH + domainNameBytes.length + usernameBytes.length +
    workstationBytes.length + lmChallengeResponse.length + ntChallengeResponse.length, pos); pos += 4; // EncryptedRandomSessionKeyOffset

  buf.writeUInt32LE(typeflags.NTLM_TYPE2_FLAGS, pos); pos += 4; // NegotiateFlags

  buf.writeUInt8(5, pos); pos++; // ProductMajorVersion
  buf.writeUInt8(1, pos); pos++; // ProductMinorVersion
  buf.writeUInt16LE(2600, pos); pos += 2; // ProductBuild
  buf.writeUInt8(0, pos); pos++; // VersionReserved1
  buf.writeUInt8(0, pos); pos++; // VersionReserved2
  buf.writeUInt8(0, pos); pos++; // VersionReserved3
  buf.writeUInt8(15, pos); pos++; // NTLMRevisionCurrent

  domainNameBytes.copy(buf, pos); pos += domainNameBytes.length;
  usernameBytes.copy(buf, pos); pos += usernameBytes.length;
  workstationBytes.copy(buf, pos); pos += workstationBytes.length;
  lmChallengeResponse.copy(buf, pos); pos += lmChallengeResponse.length;
  ntChallengeResponse.copy(buf, pos); pos += ntChallengeResponse.length;
  encryptedRandomSessionKeyBytes.copy(buf, pos); pos += encryptedRandomSessionKeyBytes.length;

  return `NTLM ${buf.toString('base64')}`;
}

function createLMHashedPasswordV1(password) {
  // fix the password length to 14 bytes
  const password2 = password.toUpperCase();
  const passwordBytes = Buffer.from(password2, 'ascii');

  const passwordBytesPadded = Buffer.alloc(14);
  passwordBytesPadded.fill('\0');
  let sourceEnd = 14;
  if (passwordBytes.length < 14) sourceEnd = passwordBytes.length;
  passwordBytes.copy(passwordBytesPadded, 0, 0, sourceEnd);

  // split into 2 parts of 7 bytes:
  const firstPart = passwordBytesPadded.slice(0, 7);
  const secondPart = passwordBytesPadded.slice(7);

  function encrypt(buf) {
    const key = insertZerosEvery7Bits(buf);
    const des = crypto.createCipheriv('DES-ECB', key, '');
    return des.update('KGS!@#$%'); // page 57 in [MS-NLMP]);
  }

  const firstPartEncrypted = encrypt(firstPart);
  const secondPartEncrypted = encrypt(secondPart);

  return Buffer.concat([firstPartEncrypted, secondPartEncrypted]);
}

function insertZerosEvery7Bits(buf) {
  const binaryArray = bytes2binaryArray(buf);
  const newBinaryArray = [];
  for (let i = 0; i < binaryArray.length; i++) {
    newBinaryArray.push(binaryArray[i]);

    if ((i + 1) % 7 === 0) {
      newBinaryArray.push(0);
    }
  }
  return binaryArray2bytes(newBinaryArray);
}

function bytes2binaryArray(buf) {
  const hex2binary = {
    0: [0, 0, 0, 0],
    1: [0, 0, 0, 1],
    2: [0, 0, 1, 0],
    3: [0, 0, 1, 1],
    4: [0, 1, 0, 0],
    5: [0, 1, 0, 1],
    6: [0, 1, 1, 0],
    7: [0, 1, 1, 1],
    8: [1, 0, 0, 0],
    9: [1, 0, 0, 1],
    A: [1, 0, 1, 0],
    B: [1, 0, 1, 1],
    C: [1, 1, 0, 0],
    D: [1, 1, 0, 1],
    E: [1, 1, 1, 0],
    F: [1, 1, 1, 1],
  };

  const hexString = buf.toString('hex').toUpperCase();
  let array = [];
  for (let i = 0; i < hexString.length; i++) {
    const hexchar = hexString.charAt(i);
    array = array.concat(hex2binary[hexchar]);
  }
  return array;
}

function binaryArray2bytes(array) {
  const binary2hex = {
    '0000': 0,
    '0001': 1,
    '0010': 2,
    '0011': 3,
    '0100': 4,
    '0101': 5,
    '0110': 6,
    '0111': 7,
    1000: 8,
    1001: 9,
    1010: 'A',
    1011: 'B',
    1100: 'C',
    1101: 'D',
    1110: 'E',
    1111: 'F',
  };

  const bufArray = [];

  for (let i = 0; i < array.length; i += 8) {
    if ((i + 7) > array.length)
    { break; }

    const binString1 = `${array[i]}${array[i + 1]}${array[i + 2]}${array[i + 3]}`;
    const binString2 = `${array[i + 4]}${array[i + 5]}${array[i + 6]}${array[i + 7]}`;
    const hexchar1 = binary2hex[binString1];
    const hexchar2 = binary2hex[binString2];

    const buf = Buffer.from(`${hexchar1}${hexchar2}`, 'hex');
    bufArray.push(buf);
  }

  return Buffer.concat(bufArray);
}

function createNTHashedPasswordV1(password) {
  const buf = Buffer.from(password, 'utf16le');
  const md4 = crypto.createHash('md4');
  md4.update(buf);
  return Buffer.from(md4.digest());
}

function calcResp(passwordHash, serverChallenge) {
  // padding with zeros to make the hash 21 bytes long
  const passHashPadded = Buffer.alloc(21);
  passHashPadded.fill('\0');
  passwordHash.copy(passHashPadded, 0, 0, passwordHash.length);

  const resArray = [];

  const des1 = crypto.createCipheriv('DES-ECB', insertZerosEvery7Bits(passHashPadded.slice(0, 7)), '');
  resArray.push(des1.update(serverChallenge.slice(0, 8)));

  const des2 = crypto.createCipheriv('DES-ECB', insertZerosEvery7Bits(passHashPadded.slice(7, 14)), '');
  resArray.push(des2.update(serverChallenge.slice(0, 8)));

  const des3 = crypto.createCipheriv('DES-ECB', insertZerosEvery7Bits(passHashPadded.slice(14, 21)), '');
  resArray.push(des3.update(serverChallenge.slice(0, 8)));

  return Buffer.concat(resArray);
}

function ntlm2srCalcResp(responseKeyNT, serverChallenge, clientChallenge) {
  // padding with zeros to make the hash 16 bytes longer
  const lmChallengeResponse = Buffer.alloc(clientChallenge.length + 16);
  lmChallengeResponse.fill('\0');
  clientChallenge.copy(lmChallengeResponse, 0, 0, clientChallenge.length);

  const buf = Buffer.concat([serverChallenge, clientChallenge]);
  const md5 = crypto.createHash('md5');
  md5.update(buf);
  const sess = md5.digest();
  const ntChallengeResponse = calcResp(responseKeyNT, sess.slice(0, 8));

  return {
    lmChallengeResponse,
    ntChallengeResponse,
  };
}

exports.createType1Message = createType1Message;
exports.parseType2Message = parseType2Message;
exports.createType3Message = createType3Message;
