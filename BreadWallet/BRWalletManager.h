//
//  BRWalletManager.h
//  TransferWallet
//
//  Created by Aaron Voisine on 3/2/14.
//  Copyright (c) 2014 Aaron Voisine <voisine@gmail.com>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#import <Foundation/Foundation.h>
#import "BRWallet.h"

#define DUFFS           100000000
#define MAX_MONEY          (21000000LL*DUFFS)
#define TRANSFER         @"TRANSFER"     // capital D with stroke (utf-8)
#define BTC          @"\xC9\x83"     // capital B with stroke (utf-8)
#define DITS         @"\xC4\x91"     // lowercase d with stroke (utf-8)
#define BITS         @"\xC6\x80"     // lowercase b with stroke (utf-8)
#define NARROW_NBSP  @"\xE2\x80\xAF" // narrow no-break space (utf-8)
#define LDQUOTE      @"\xE2\x80\x9C" // left double quote (utf-8)
#define RDQUOTE      @"\xE2\x80\x9D" // right double quote (utf-8)
#define DISPLAY_NAME [NSString stringWithFormat:LDQUOTE @"%@" RDQUOTE,\
NSBundle.mainBundle.infoDictionary[@"CFBundleDisplayName"]]

#define WALLET_NEEDS_BACKUP_KEY                @"WALLET_NEEDS_BACKUP"
#define BRWalletManagerSeedChangedNotification @"BRWalletManagerSeedChangedNotification"

@protocol BRMnemonic;

@interface BRWalletManager : NSObject<UIAlertViewDelegate, UITextFieldDelegate, UITextViewDelegate>

@property (nonatomic, readonly) BRWallet *wallet;
@property (nonatomic, readonly) BOOL noWallet; // true if keychain is available and we know that no wallet exists on it
@property (nonatomic, strong) id<BRKeySequence> sequence;
@property (nonatomic, strong) id<BRMnemonic> mnemonic;
@property (nonatomic, readonly) NSData *masterPublicKey; // master public key used to generate wallet addresses
@property (nonatomic, copy) NSString *seedPhrase; // requesting seedPhrase will trigger authentication
@property (nonatomic, readonly) NSTimeInterval seedCreationTime; // interval since refrence date, 00:00:00 01/01/01 GMT
@property (nonatomic, readonly) NSTimeInterval secureTime; // last known time from an ssl server connection
@property (nonatomic, assign) uint64_t spendingLimit; // amount that can be spent using touch id without pin entry
@property (nonatomic, readonly, getter=isTouchIdEnabled) BOOL touchIdEnabled; // true if touch id is enabled
@property (nonatomic, readonly, getter=isPasscodeEnabled) BOOL passcodeEnabled; // true if device passcode is enabled
@property (nonatomic, assign) BOOL didAuthenticate; // true if the user authenticated after this was last set to false
@property (nonatomic, readonly) NSNumberFormatter *transferFormat; // transfer currency formatter
@property (nonatomic, readonly) NSNumberFormatter *bitcoinFormat; // bitcoin currency formatter
@property (nonatomic, readonly) NSNumberFormatter *unknownFormat; // unknown currency formatter
@property (nonatomic, readonly) NSNumberFormatter *localFormat; // local currency formatter
@property (nonatomic, copy) NSString *localCurrencyCode; // local currency ISO code
@property (nonatomic, readonly) double localCurrencyBitcoinPrice; // exchange rate in local currency units per bitcoin
@property (nonatomic, readonly) double bitcoinTransferPrice; // exchange rate in bitcoin per transfer
@property (nonatomic, readonly) NSArray *currencyCodes; // list of supported local currency codes
@property (nonatomic, readonly) NSArray *currencyNames; // names for local currency codes
@property (nonatomic, assign) size_t averageBlockSize; // set this to enable basic floating fee calculation

+ (instancetype)sharedInstance;

- (NSString *)generateRandomSeed; // generates a random seed, saves to keychain and returns the associated seedPhrase
- (NSData *)seedWithPrompt:(NSString *)authprompt forAmount:(uint64_t)amount; // authenticates user and returns seed
- (NSString *)seedPhraseWithPrompt:(NSString *)authprompt; // authenticates user and returns seedPhrase
- (BOOL)authenticateWithPrompt:(NSString *)authprompt andTouchId:(BOOL)touchId; // prompts user to authenticate
- (BOOL)setPin; // prompts the user to set or change wallet pin and returns true if the pin was successfully set

// queries chain.com and calls the completion block with unspent outputs for the given address
- (void)utxosForAddress:(NSString *)address
completion:(void (^)(NSArray *utxos, NSArray *amounts, NSArray *scripts, NSError *error))completion;

// given a private key, queries chain.com for unspent outputs and calls the completion block with a signed transaction
// that will sweep the balance into wallet (doesn't publish the tx)
- (void)sweepPrivateKey:(NSString *)privKey withFee:(BOOL)fee
completion:(void (^)(BRTransaction *tx, uint64_t fee, NSError *error))completion;

- (int64_t)amountForUnknownCurrencyString:(NSString *)string;
- (int64_t)amountForTransferString:(NSString *)string;
- (int64_t)amountForBitcoinString:(NSString *)string;
- (NSString *)transferStringForAmount:(int64_t)amount;
- (NSAttributedString *)attributedTransferStringForAmount:(int64_t)amount;
- (NSAttributedString *)attributedTransferStringForAmount:(int64_t)amount withTintColor:(UIColor*)color transferSymbolSize:(CGSize)transferSymbolSize;
- (NSNumber *)numberForAmount:(int64_t)amount;
- (NSString *)bitcoinStringForAmount:(int64_t)amount;
- (int64_t)amountForBitcoinCurrencyString:(NSString *)string;
- (int64_t)amountForLocalCurrencyString:(NSString *)string;
- (NSString *)bitcoinCurrencyStringForAmount:(int64_t)amount;
- (NSString *)localCurrencyStringForTransferAmount:(int64_t)amount;
- (NSString *)localCurrencyStringForBitcoinAmount:(int64_t)amount;

@end
