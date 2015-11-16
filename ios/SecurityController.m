//
//  SecurityController.m
//  RCTSecureElement
//
//  Created by Hasan Ali Gulez on 05/10/2015.
//  Copyright © 2015 Facebook. All rights reserved.
//

#import "SecurityController.h"

@interface SecurityController ()

@end

size_t BUFFER_SIZE = 64;//64
size_t CIPHER_BUFFER_SIZE = 1024;//1024
const uint32_t PADDING = kSecPaddingNone; //kSecPaddingPKCS1
static const UInt8 publicKeyIdentifier[] = "com.apple.sample.publickey";
static const UInt8 privateKeyIdentifier[] = "com.apple.sample.privatekey";
NSString *keyType = @"EC";

@implementation SecurityController

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(generatePair:(NSString *)inputKeyType callback:(RCTResponseSenderBlock)callback)
{
  keyType = inputKeyType ;
  
  privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
  publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
  
  //[self verifyTestRun] ;
  //[self testRun] ;
  
  [self getPublicKeyRef] ;
  NSString *publicKeyTagString = [[NSString alloc] initWithBytes:publicKeyIdentifier
                                          length:sizeof(publicKeyIdentifier)
                                        encoding:NSUTF8StringEncoding] ;
  
  callback(@[publicKeyTagString]);
}

RCT_EXPORT_METHOD(encryptInputString:(NSString *)inputString inputKeyTag:(NSString *)inputKeyTag callback:(RCTResponseSenderBlock)callback)
{
//INITIALISE
  
  publicTag = [inputKeyTag dataUsingEncoding:NSUTF8StringEncoding];
  SecKeyRef publicKeyRef = [self getPublicKeyRef] ;
  
  uint8_t *plainBuffer;
  uint8_t *cipherBuffer;
  
  const char *innerInputString = inputString.UTF8String  ;
  int len = strlen(innerInputString);
  // TODO: this is a hack since i know inputString length will be less than BUFFER_SIZE
  if (len > BUFFER_SIZE) len = BUFFER_SIZE-1;
  
  plainBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
  cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));

  strncpy( (char *)plainBuffer, innerInputString, len);
  
//ENCRYPT
  OSStatus status = noErr;
  size_t plainBufferSize = strlen((char *)plainBuffer);
  size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
  status = SecKeyEncrypt(publicKeyRef,
                         PADDING,
                         plainBuffer,
                         plainBufferSize,
                         &cipherBuffer[0],
                         &cipherBufferSize
                         );
  
  
//CONVERT TO NSSTRING
  NSData *theData = [NSData dataWithBytes:(const void *)cipherBuffer length:CIPHER_BUFFER_SIZE];
  NSString *base64String = [theData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
  
  callback(@[base64String]);
}

RCT_EXPORT_METHOD(decryptCipher:(NSString *)inputCipher callback:(RCTResponseSenderBlock)callback)
{
//CONVERT NSSTRING TO UINT_8
  NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:inputCipher options:NSDataBase64Encoding64CharacterLineLength];
  uint8_t *encryptedBuffer = (const uint8_t*)[decodedData bytes];

//INITIALISE
  uint8_t *decryptedBuffer;
  decryptedBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));

//DECRYPT
  OSStatus status = noErr;
  size_t encryptedBufferSize = strlen((char *)encryptedBuffer);
  size_t decryptedBufferSize = BUFFER_SIZE;
  status = SecKeyDecrypt([self getPrivateKeyRef],
                         PADDING,
                         &encryptedBuffer[0],
                         encryptedBufferSize,
                         &decryptedBuffer[0],
                         &decryptedBufferSize
                         );
  
  NSString *clearText = [NSString stringWithFormat:@"%s", decryptedBuffer];
  callback(@[clearText]);
}

RCT_EXPORT_METHOD(sign:(NSString *)inputString callback:(RCTResponseSenderBlock)callback){
 
  NSData *plainText = [inputString dataUsingEncoding:NSUTF8StringEncoding];
  NSData *signedHash = [self getSignatureBytes:plainText] ;
  NSString *base64String = [[NSString alloc] initWithData:signedHash encoding:NSNEXTSTEPStringEncoding];

  callback(@[base64String]) ;
}

RCT_EXPORT_METHOD(verify:(NSString *)inputString inputKeyTag:(NSString *)publicKeyTag signedHash:(NSString *)signedHashString callback:(RCTResponseSenderBlock)callback){
  
  //set public key from input identifier
  publicTag = [publicKeyTag dataUsingEncoding:NSUTF8StringEncoding];
  SecKeyRef publicKeyRef = [self getPublicKeyRef] ;

  //convert plaintext to nsdata
  NSData *plainText = [inputString dataUsingEncoding:NSUTF8StringEncoding] ;
  
  //convert signedHash to nsdata
  NSData *signedHash = [signedHashString dataUsingEncoding:NSNEXTSTEPStringEncoding] ;
  
  BOOL sanityCheck = [self verifySignature:plainText secKeyRef:publicKeyRef signature:signedHash] ;
  
  NSString *base64String = sanityCheck ? @"YES" : @"NO" ;
  
  callback(@[base64String]) ;
}

#pragma mark - Test methods without data type conversion

- (void) testRun {
  
//INITIALISE
  privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
  publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
  NSString *inputData = @"bear & fox" ;
  SecKeyRef publicKeyRef = [self getPublicKeyRef] ;

  uint8_t *plainBuffer;
  uint8_t *cipherBuffer;
  uint8_t *decryptedBuffer;
  const char *inputString = inputData.UTF8String  ;
  
  int len = strlen(inputString);
  if (len > BUFFER_SIZE) len = BUFFER_SIZE-1;
  
  plainBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
  cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
  decryptedBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));

  strncpy( (char *)plainBuffer, inputString, len);
  
//ENCRYPT
  OSStatus status = noErr;
  size_t plainBufferSize = strlen((char *)plainBuffer);
  size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
  status = SecKeyEncrypt(publicKeyRef,
                         PADDING,
                         plainBuffer,
                         plainBufferSize,
                         &cipherBuffer[0],
                         &cipherBufferSize
                         );

//Convert unint_8 to String
  NSData *theData = [NSData dataWithBytes:(const void *)cipherBuffer length:CIPHER_BUFFER_SIZE];
  NSString *base64String = [theData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

//Convert String to uint_8
  NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:base64String options:NSDataBase64Encoding64CharacterLineLength];
  uint8_t *encryptedBuffer = (const uint8_t*)[decodedData bytes];

//DECRYPT
  size_t encryptedBufferSize = strlen((char *)encryptedBuffer);
  size_t decryptedBufferSize = BUFFER_SIZE;
  status = SecKeyDecrypt([self getPrivateKeyRef],
                         PADDING,
                         &encryptedBuffer[0],
                         encryptedBufferSize,
                         &decryptedBuffer[0],
                         &decryptedBufferSize
                         );

  NSLog(@"clearText -> %@",[NSString stringWithFormat:@"%s", decryptedBuffer]) ;
}

- (void) verifyTestRun {
  
  NSData *plainText = [@"bear and fox" dataUsingEncoding:NSUTF8StringEncoding];

  NSData *signedHash = [self getSignatureBytes:plainText] ;
  
  BOOL sanityCheck = [self verifySignature:plainText secKeyRef:[self getPublicKeyRef] signature:signedHash] ;
  
}

#pragma mark - iOS side Verify & Sign methods

- (NSData *)getSignatureBytes:(NSData *)plainText {
  
  //Initialise
  OSStatus sanityCheck = noErr;
  NSData * signedHash = nil;
  uint8_t * signedHashBytes = NULL;
  size_t signedHashBytesSize = 0;
  SecKeyRef privateKeyRef = NULL;
  
  //private key allocation.
  privateKeyRef = [self getPrivateKeyRef];
  
  signedHashBytesSize = SecKeyGetBlockSize(privateKeyRef);
  
  // Malloc a buffer to hold signature.
  signedHashBytes = malloc( signedHashBytesSize * sizeof(uint8_t) );
  memset((void *)signedHashBytes, 0x0, signedHashBytesSize);
  
  // Sign the SHA1 hash.
  sanityCheck = SecKeyRawSign(privateKeyRef,
                              PADDING,
                              (const uint8_t *)[[self getHashBytes:plainText] bytes],
                              kChosenDigestLength,
                              (uint8_t *)signedHashBytes,
                              &signedHashBytesSize
                              );
  
  //  LOGGING_FACILITY1( sanityCheck == noErr, @"Problem signing the SHA1 hash, OSStatus == %d.", sanityCheck );
  
  // Build up signed SHA1 blob.
  signedHash = [NSData dataWithBytes:(const void *)signedHashBytes length:(NSUInteger)signedHashBytesSize];
  if (signedHashBytes) free(signedHashBytes);
  
  return signedHash;
}

- (NSData *)getHashBytes:(NSData *)plainText {
  
  CC_SHA1_CTX ctx;
  uint8_t * hashBytes = NULL;
  NSData * hash = nil;
  
  // Malloc a buffer to hold hash.
  hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
  memset((void *)hashBytes, 0x0, kChosenDigestLength);
  
  
  // Initialize the context.
  CC_SHA1_Init(&ctx);
  // Perform the hash.
  CC_SHA1_Update(&ctx, (void *)[plainText bytes], [plainText length]);
  // Finalize the output.
  CC_SHA1_Final(hashBytes, &ctx);
  
  
  // Build up the SHA1 blob.
  hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];
  
  if (hashBytes) free(hashBytes);
  
  return hash;
}

- (BOOL)verifySignature:(NSData *)plainText secKeyRef:(SecKeyRef)publicKey signature:(NSData *)sig {
  size_t signedHashBytesSize = 0;
  OSStatus sanityCheck = noErr;
  
  // Get the size of the assymetric block.
  signedHashBytesSize = SecKeyGetBlockSize(publicKey);
  
  sanityCheck = SecKeyRawVerify(  publicKey,
                                PADDING,
                                (const uint8_t *)[[self getHashBytes:plainText] bytes],
                                kChosenDigestLength,
                                (const uint8_t *)[sig bytes],
                                signedHashBytesSize
                                );
  
  return (sanityCheck == noErr) ? YES : NO;
}


#pragma mark - iOS side Encryption & Decryption methods

- (SecKeyRef)getPublicKeyRef {
  
  OSStatus sanityCheck = noErr;
  SecKeyRef publicKeyReference = NULL;
  
  if (publicKeyReference == NULL) {
    [self generateKeyPair:512];
    NSMutableDictionary *queryPublicKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    
    // Get the key.
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
    
    
    if (sanityCheck != noErr)
    {
      publicKeyReference = NULL;
    }
    
    
    //        [queryPublicKey release];
    
  } else { publicKeyReference = publicKey; }
  
  return publicKeyReference;
}

- (SecKeyRef)getPrivateKeyRef {
  OSStatus resultCode = noErr;
  SecKeyRef privateKeyReference = NULL;
  //    NSData *privateTag = [NSData dataWithBytes:@"ABCD" length:strlen((const char *)@"ABCD")];
  //    if(privateKey == NULL) {
  [self generateKeyPair:512];
  NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
  
  // Set the private key query dictionary.
  [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
  [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
  [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
  [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
  
  // Get the key.
  resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
//  NSLog(@"getPrivateKey: result code: %ld", resultCode);
  
  if(resultCode != noErr)
  {
    privateKeyReference = NULL;
  }
  
  //        [queryPrivateKey release];
  //    } else {
  //        privateKeyReference = privateKey;
  //    }
  
  return privateKeyReference;
}

- (void)generateKeyPair:(NSUInteger)keySize {
  OSStatus sanityCheck = noErr;
  publicKey = NULL;
  privateKey = NULL;
  
  //  LOGGING_FACILITY1( keySize == 512 || keySize == 1024 || keySize == 2048, @"%d is an invalid and unsupported key size.", keySize );
  
  // Container dictionaries.
  NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
  NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
  NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
  
  // Set top level dictionary for the keypair.
  if ([keyType isEqualToString:@"RSA"]) {
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
  }else{
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeEC forKey:(__bridge id)kSecAttrKeyType];
  }
  [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
  
  // Set the private key dictionary.
  [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
  [privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
  // See SecKey.h to set other flag values.
  
  // Set the public key dictionary.
  [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
  [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
  // See SecKey.h to set other flag values.
  
  // Set attributes to top level dictionary.
  [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
  [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
  
  // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
  sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);

//  if(sanityCheck == noErr  && publicKey != NULL && privateKey != NULL)
//  {
//    NSLog(@"Successful");
//  }
}



/*
- (NSData *)signData:(NSData *)data withIndentity:(SecIdentityRef)identity
{
  // FIXME: cleanup cf leaks
  SecGroupTransformRef group = SecTransformCreateGroupTransform();
  CFReadStreamRef readStream = NULL;
  SecTransformRef readTransform = NULL;
  SecTransformRef signingTransform = NULL;
  CFErrorRef err = NULL;
  
  SecKeyRef privateKey;
  OSStatus ret = SecIdentityCopyPrivateKey(identity, &privateKey);
  if (ret) {
    NSLog(@"fail");
    return nil;
  }
  
  // Setup our input stream as well as an input transform
  readStream = CFReadStreamCreateWithBytesNoCopy(kCFAllocatorDefault, [data bytes], [data length], kCFAllocatorNull);
  
  readTransform = SecTransformCreateReadTransformWithReadStream(readStream);
  
  // Setup a signing transform
  signingTransform = SecSignTransformCreate(privateKey, &err);
  if (err) {
    NSLog(@"SecSignTransformCreate failed: %@", (__bridge NSError *)err);
    return nil;
  }
  SecTransformSetAttribute(signingTransform, kSecInputIsDigest, kCFBooleanTrue, &err);
  if (err) {
    NSLog(@"SecTransformSetAttribute:kSecInputIsDigest failed: %@", (__bridge NSError *)err);
    return nil;
  }
  SecTransformSetAttribute(signingTransform, kSecDigestTypeAttribute, kSecDigestSHA1, &err);
  if (err) {
    NSLog(@"SecTransformSetAttribute:kSecDigestTypeAttribute failed: %@", (__bridge NSError *)err);
    return nil;
  }
  
  // Connect read and signing transform; Have read pass its data to the signer
  SecTransformConnectTransforms(readTransform, kSecTransformOutputAttributeName,
                                signingTransform, kSecTransformInputAttributeName,
                                group, &err);
  if (err) {
    NSLog(@"SecTransformConnectTransforms failed: %@", (__bridge NSError *)err);
    return nil;
  }
  
  // Execute the sequence of transforms (group)
  // The last one in the connected sequence is the return value
  CFTypeRef cfRet = SecTransformExecute(group, &err);
  if (err) {
    NSLog(@"SecTransformExecute failed: %@", (__bridge NSError *)err);
    return nil;
  }
  return (__bridge_transfer NSData *)cfRet;
}
*/

/* Code Borrowed from:
 * http://stackoverflow.com/questions/10072124/iphone-how-to-encrypt-nsdata-with-public-key-and-decrypt-with-private-key
 * https://developer.apple.com/library/mac/#documentation/security/conceptual/CertKeyTrustProgGuide/iPhone_Tasks/iPhone_Tasks.html
 */

@end
