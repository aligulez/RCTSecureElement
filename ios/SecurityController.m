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
  
//  BUFFER_SIZE = len ;
//  CIPHER_BUFFER_SIZE = len * 16 ;
  
  privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
  publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
  
  [self getPublicKeyRef] ;
  NSString *publicKeyTagString = [[NSString alloc] initWithBytes:publicKeyIdentifier
                                          length:sizeof(publicKeyIdentifier)
                                        encoding:NSUTF8StringEncoding] ;
  
  callback(@[publicKeyTagString]);
  NSLog(@"I made some changes") ;
  
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

-(void) testRun {
  
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

#pragma mark - iOS side security methods
//http://stackoverflow.com/questions/10072124/iphone-how-to-encrypt-nsdata-with-public-key-and-decrypt-with-private-key

-(SecKeyRef)getPublicKeyRef {
  
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


/* Borrowed from:
 * https://developer.apple.com/library/mac/#documentation/security/conceptual/CertKeyTrustProgGuide/iPhone_Tasks/iPhone_Tasks.html
 */

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



@end
