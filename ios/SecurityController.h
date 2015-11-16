//
//  SecurityController.h
//  RCTSecureElement
//
//  Created by Hasan Ali Gulez on 05/10/2015.
//  Copyright © 2015 Facebook. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "RCTBridgeModule.h"
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#define kChosenDigestLength		CC_SHA1_DIGEST_LENGTH

@interface SecurityController :  NSObject <RCTBridgeModule>{
  SecKeyRef publicKey;
  SecKeyRef privateKey;
  NSData *publicTag;
  NSData *privateTag;
}

- (void)decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer;
- (SecKeyRef)getPublicKeyRef;
- (SecKeyRef)getPrivateKeyRef;
- (void)generateKeyPair:(NSUInteger)keySize;

@end
