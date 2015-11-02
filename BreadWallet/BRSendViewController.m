//
//  BRSendViewController.m
//  TransferWallet
//
//  Created by Aaron Voisine on 5/8/13.
//  Copyright (c) 2013 Aaron Voisine <voisine@gmail.com>
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

#import "BRSendViewController.h"
#import "BRRootViewController.h"
#import "BRScanViewController.h"
#import "BRAmountViewController.h"
#import "BRSettingsViewController.h"
#import "BRBubbleView.h"
#import "BRWalletManager.h"
#import "BRPeerManager.h"
#import "BRPaymentRequest.h"
#import "BRPaymentProtocol.h"
#import "BRKey.h"
#import "BRTransaction.h"

#import "DCShapeshiftManager.h"
#import "DCShapeshiftEntity.h"

#import "FBShimmeringView.h"
#import "MBProgressHUD.h"

#import "NSString+Transfer.h"
#import "NSString+Bitcoin.h"
#import "NSMutableData+Bitcoin.h"
#import "NSData+Transfer.h"

#define SCAN_TIP      NSLocalizedString(@"Scan someone else's QR code to get their transfer address. "\
"You can send a payment to anyone with an address.", nil)
#define CLIPBOARD_TIP NSLocalizedString(@"Transfer addresses can also be copied to the clipboard. A transfer address always starts with 'X' or 'Y'.", nil)

#define LOCK @"\xF0\x9F\x94\x92" // unicode lock symbol U+1F512 (utf-8)
#define REDX @"\xE2\x9D\x8C"     // unicode cross mark U+274C, red x emoji (utf-8)
#define NBSP @"\xC2\xA0"         // no-break space (utf-8)

static NSString *sanitizeString(NSString *s)
{
    NSMutableString *sane = [NSMutableString stringWithString:(s) ? s : @""];
    
    CFStringTransform((CFMutableStringRef)sane, NULL, kCFStringTransformToUnicodeName, NO);
    return sane;
}

@interface BRSendViewController ()

@property (nonatomic, assign) BOOL clearClipboard, useClipboard, showTips, showBalance, canChangeAmount;
@property (nonatomic, strong) BRTransaction *sweepTx;
@property (nonatomic, strong) BRPaymentProtocolRequest *request;
@property (nonatomic, strong) NSURL *url;
@property (nonatomic, assign) uint64_t amount;
@property (nonatomic, strong) NSString *okAddress, *okIdentity;
@property (nonatomic, strong) BRBubbleView *tipView;
@property (nonatomic, strong) BRScanViewController *scanController;
@property (nonatomic, strong) id clipboardObserver;

@property (nonatomic, strong) IBOutlet UILabel *sendLabel;
@property (nonatomic, strong) IBOutlet UIButton *scanButton, *clipboardButton;
@property (nonatomic, strong) IBOutlet UITextView *clipboardText;
@property (nonatomic, strong) IBOutlet NSLayoutConstraint *clipboardXLeft;
@property (nonatomic, strong) IBOutlet UIView * shapeshiftView;
@property (nonatomic, strong) IBOutlet UILabel * shapeshiftLabel;

@end

@implementation BRSendViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    // TODO: XXX redesign page with round buttons like the iOS power down screen... apple watch also has round buttons
    self.scanButton.titleLabel.adjustsFontSizeToFitWidth = YES;
    self.clipboardButton.titleLabel.adjustsFontSizeToFitWidth = YES;
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    self.scanButton.titleLabel.adjustsLetterSpacingToFitWidth = YES;
    self.clipboardButton.titleLabel.adjustsLetterSpacingToFitWidth = YES;
#pragma clang diagnostic pop
    
    self.clipboardText.textContainerInset = UIEdgeInsetsMake(8.0, 0.0, 0.0, 0.0);
    
    self.clipboardObserver =
    [[NSNotificationCenter defaultCenter] addObserverForName:UIPasteboardChangedNotification object:nil queue:nil
                                                  usingBlock:^(NSNotification *note) {
                                                      if (self.clipboardText.isFirstResponder) {
                                                          self.useClipboard = YES;
                                                      }
                                                      else [self updateClipboardText];
                                                  }];
    
    FBShimmeringView *shimmeringView = [[FBShimmeringView alloc] initWithFrame:self.shapeshiftView.frame];
    [self.view addSubview:shimmeringView];
    [self.shapeshiftView removeFromSuperview];
    [shimmeringView addSubview:self.shapeshiftView];
    shimmeringView.contentView = self.shapeshiftView;
    // Start shimmering.
    shimmeringView.shimmering = YES;
    shimmeringView.shimmeringSpeed = 5;
    shimmeringView.shimmeringDirection = FBShimmerDirectionUp;
    shimmeringView.shimmeringPauseDuration = 0.0;
    shimmeringView.shimmeringHighlightLength = 1.0f;
    shimmeringView.shimmeringAnimationOpacity = 0.8;
    self.shapeshiftView = shimmeringView;
    
    FBShimmeringView *shimmeringInnerLabelView = [[FBShimmeringView alloc] initWithFrame:self.shapeshiftLabel.frame];
    [self.shapeshiftLabel removeFromSuperview];
    [shimmeringInnerLabelView addSubview:self.shapeshiftLabel];
    shimmeringInnerLabelView.contentView = self.shapeshiftLabel;
    
    shimmeringInnerLabelView.shimmering = YES;
    shimmeringInnerLabelView.shimmeringSpeed = 100;
    shimmeringInnerLabelView.shimmeringPauseDuration = 0.8;
    shimmeringInnerLabelView.shimmeringAnimationOpacity = 0.2;
    [self.shapeshiftView addSubview:shimmeringInnerLabelView];
    NSArray * shapeshiftsInProgress = [DCShapeshiftEntity shapeshiftsInProgress];
    if (![shapeshiftsInProgress count]) {
        
        self.shapeshiftView.hidden = TRUE;
    } else {
        for (DCShapeshiftEntity * shapeshift in shapeshiftsInProgress) {
            [shapeshift transaction];
            [self startObservingShapeshift:shapeshift];
        }
    }
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    [self cancel:nil];
}

- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];
    
    if (! self.scanController) {
        self.scanController = [self.storyboard instantiateViewControllerWithIdentifier:@"ScanViewController"];
    }
}

- (void)viewWillDisappear:(BOOL)animated
{
    [self hideTips];
    [super viewWillDisappear:animated];
}

- (void)dealloc
{
    if (self.clipboardObserver) [[NSNotificationCenter defaultCenter] removeObserver:self.clipboardObserver];
}

- (void)handleURL:(NSURL *)url
{
    //TODO: XXX custom url splash image per: "Providing Launch Images for Custom URL Schemes."
    BRWalletManager *m = [BRWalletManager sharedInstance];
    
    if ([url.scheme isEqual:@"transferwallet"]) { // x-callback-url handling: http://x-callback-url.com/specifications/
        NSString *xsource = nil, *xsuccess = nil, *xerror = nil;
        NSURL *callback = nil;
        
        for (NSString *arg in [url.query componentsSeparatedByString:@"&"]) {
            NSArray *pair = [arg componentsSeparatedByString:@"="]; // if more than one '=', then pair[1] != value
            
            if (pair.count < 2) continue;
            
            NSString *value = [[[arg substringFromIndex:[pair[0] length] + 1]
                                stringByReplacingOccurrencesOfString:@"+" withString:@" "]
                               stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
            
            if ([pair[0] isEqual:@"x-source"]) xsource = value;
            else if ([pair[0] isEqual:@"x-success"]) xsuccess = value;
            else if ([pair[0] isEqual:@"x-error"]) xerror = value;
        }
        
        if ([url.host isEqual:@"scanqr"] || [url.path isEqual:@"/scanqr"]) { // scan qr
            [self scanQR:nil];
        }
        else if ([url.host isEqual:@"addresslist"] || [url.path isEqual:@"/addresslist"]) { // copy wallet addresses
            if ((m.didAuthenticate || [m authenticateWithPrompt:nil andTouchId:YES]) && ! self.clearClipboard) {
                if (! [self.url isEqual:url]) {
                    self.url = url;
                    [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"copy wallet addresses to clipboard?", nil)
                                                message:nil delegate:self cancelButtonTitle:NSLocalizedString(@"cancel", nil)
                                      otherButtonTitles:NSLocalizedString(@"copy", nil), nil] show];
                }
                else {
                    [[UIPasteboard generalPasteboard]
                     setString:[[[m.wallet.addresses objectsPassingTest:^BOOL(id obj, BOOL *stop) {
                        return [m.wallet addressIsUsed:obj];
                    }] allObjects] componentsJoinedByString:@"\n"]];
                    
                    if (xsuccess) callback = [NSURL URLWithString:xsuccess];
                    self.url = nil;
                }
            }
            else if (xerror || xsuccess) {
                callback = [NSURL URLWithString:(xerror) ? xerror : xsuccess];
                [[UIPasteboard generalPasteboard] setString:@""];
                [self cancel:nil];
            }
        }
        else if ([url.path isEqual:@"/address"] && xsuccess) { // get receive address
            callback = [NSURL URLWithString:[xsuccess stringByAppendingFormat:@"%@address=%@",
                                             ([[[NSURL URLWithString:xsuccess] query] length] > 0) ? @"&" : @"?",
                                             m.wallet.receiveAddress]];
        }
        
        if (callback && [[UIApplication sharedApplication] canOpenURL:callback]) {
            [[UIApplication sharedApplication] openURL:callback];
        }
    }
    else if ([url.scheme isEqual:@"transfer"] || [url.scheme isEqual:@"bitcoin"]) {
        [self confirmRequest:[BRPaymentRequest requestWithURL:url]];
    }
    else {
        [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"unsupported url", nil) message:url.absoluteString
                                   delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
    }
}

- (void)handleFile:(NSData *)file
{
    BRPaymentProtocolRequest *request = [BRPaymentProtocolRequest requestWithData:file];
    
    if (request) {
        [self confirmProtocolRequest:request];
        return;
    }
    
    // TODO: reject payments that don't match requested amounts/scripts, implement refunds
    BRPaymentProtocolPayment *payment = [BRPaymentProtocolPayment paymentWithData:file];
    
    if (payment.transactions.count > 0) {
        for (BRTransaction *tx in payment.transactions) {
            [(id)self.parentViewController.parentViewController startActivityWithTimeout:30];
            
            [[BRPeerManager sharedInstance] publishTransaction:tx completion:^(NSError *error) {
                [(id)self.parentViewController.parentViewController stopActivityWithSuccess:(! error)];
                
                if (error) {
                    [[[UIAlertView alloc]
                      initWithTitle:NSLocalizedString(@"couldn't transmit payment to transfer network", nil)
                      message:error.localizedDescription delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil)
                      otherButtonTitles:nil] show];
                }
                
                [self.view addSubview:[[[BRBubbleView
                                         viewWithText:(payment.memo.length > 0 ? payment.memo : NSLocalizedString(@"received", nil))
                                         center:CGPointMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2)] popIn]
                                       popOutAfterDelay:(payment.memo.length > 0 ? 3.0 : 2.0)]];
            }];
        }
        
        return;
    }
    
    BRPaymentProtocolACK *ack = [BRPaymentProtocolACK ackWithData:file];
    
    if (ack) {
        if (ack.memo.length > 0) {
            [self.view addSubview:[[[BRBubbleView viewWithText:ack.memo
                                                        center:CGPointMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2)] popIn]
                                   popOutAfterDelay:3.0]];
        }
        
        return;
    }
    
    [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"unsupported or corrupted document", nil) message:nil
                               delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
}

- (NSString *)promptForAmount:(uint64_t)amount fee:(uint64_t)fee address:(NSString *)address name:(NSString *)name
                         memo:(NSString *)memo isSecure:(BOOL)isSecure
{
    BRWalletManager *m = [BRWalletManager sharedInstance];
    NSString *prompt = (isSecure && name.length > 0) ? LOCK @" " : @"";
    
    //BUG: XXX limit the length of name and memo to avoid having the amount clipped
    if (! isSecure && self.request.errorMessage.length > 0) prompt = [prompt stringByAppendingString:REDX @" "];
    if (name.length > 0) prompt = [prompt stringByAppendingString:sanitizeString(name)];
    if (! isSecure && prompt.length > 0) prompt = [prompt stringByAppendingString:@"\n"];
    if (! isSecure || prompt.length == 0) prompt = [prompt stringByAppendingString:address];
    if (memo.length > 0) prompt = [prompt stringByAppendingFormat:@"\n\n%@", sanitizeString(memo)];
    prompt = [prompt stringByAppendingFormat:NSLocalizedString(@"\n\n     amount %@ (%@)", nil),
              [m transferStringForAmount:amount - fee], [m localCurrencyStringForTransferAmount:amount - fee]];
    
    if (fee > 0) {
        prompt = [prompt stringByAppendingFormat:NSLocalizedString(@"\nnetwork fee +%@ (%@)", nil),
                  [m transferStringForAmount:fee], [m localCurrencyStringForTransferAmount:fee]];
        prompt = [prompt stringByAppendingFormat:NSLocalizedString(@"\n         total %@ (%@)", nil),
                  [m transferStringForAmount:amount], [m localCurrencyStringForTransferAmount:amount]];
    }
    
    return prompt;
}

- (void)confirmRequest:(BRPaymentRequest *)request
{
    if (![request isValid]) {
        if ([request.paymentAddress isValidDigitalCashPrivateKey] || [request.paymentAddress isValidDigitalCashBIP38Key]) {
            [self confirmSweep:request.paymentAddress];
        }
        else {
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"not a valid transfer address", nil)
                                        message:request.paymentAddress delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil)
                              otherButtonTitles:nil] show];
            [self cancel:nil];
        }
    }
    else if (request.r.length > 0) { // payment protocol over HTTP
        [(id)self.parentViewController.parentViewController startActivityWithTimeout:20.0];
        
        [BRPaymentRequest fetch:request.r type:request.type timeout:20.0 completion:^(BRPaymentProtocolRequest *req, NSError *error) {
            [(id)self.parentViewController.parentViewController stopActivityWithSuccess:(! error)];
            
            if (error && (![request.paymentAddress isValidBitcoinAddress] && ![request.paymentAddress isValidDigitalCashAddress])) {
                [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't make payment", nil)
                                            message:error.localizedDescription delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil)
                                  otherButtonTitles:nil] show];
                [self cancel:nil];
            }
            else [self confirmProtocolRequest:(error) ? request.protocolRequest : req];
        }];
    }
    else [self confirmProtocolRequest:request.protocolRequest currency:request.type associatedShapeshift:nil];
}

- (void)confirmProtocolRequest:(BRPaymentProtocolRequest *)protoReq {
    [self confirmProtocolRequest:protoReq currency:@"transfer" associatedShapeshift:nil];
}

- (void)confirmProtocolRequest:(BRPaymentProtocolRequest *)protoReq currency:(NSString*)currency associatedShapeshift:(DCShapeshiftEntity*)shapeshift
{
    NSString *address;
    if ([currency isEqualToString:@"bitcoin"]) {
        address = [NSString bitcoinAddressWithScriptPubKey:protoReq.details.outputScripts.firstObject];

    } else {
        address = [NSString addressWithScriptPubKey:protoReq.details.outputScripts.firstObject];
    }
    BOOL valid = [protoReq isValid], outputTooSmall = NO;
    
    if (! valid && [protoReq.errorMessage isEqual:NSLocalizedString(@"request expired", nil)]) {
        [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"bad payment request", nil) message:protoReq.errorMessage
                                   delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
        [self cancel:nil];
        return;
    }
    
    uint64_t amount = 0, fee = 0;
    
    //TODO: check for duplicates of already paid requests
    
    if (self.amount == 0) {
        for (NSNumber *n in protoReq.details.outputAmounts) {
            if ([n unsignedLongLongValue] > 0 && [n unsignedLongLongValue] < TX_MIN_OUTPUT_AMOUNT) outputTooSmall = YES;
            amount += [n unsignedLongLongValue];
        }
    }
    else amount = self.amount;
    
    if ([currency isEqualToString:@"transfer"]) {
        
        BRWalletManager *m = [BRWalletManager sharedInstance];
        BRTransaction *tx = nil;
        
        
        if ([m.wallet containsAddress:address]) {
            [[[UIAlertView alloc] initWithTitle:@""
                                        message:NSLocalizedString(@"this payment address is already in your wallet", nil)
                                       delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
            [self cancel:nil];
            return;
        }
        else if (! [self.okAddress isEqual:address] && [m.wallet addressIsUsed:address] &&
                 [[[UIPasteboard generalPasteboard] string] isEqual:address]) {
            self.request = protoReq;
            self.okAddress = address;
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"WARNING", nil)
                                        message:NSLocalizedString(@"\nADDRESS ALREADY USED\n\ntransfer addresses are intended for single use only\n\n"
                                                                  "re-use reduces privacy for both you and the recipient and can result in loss if "
                                                                  "the recipient doesn't directly control the address", nil)
                                       delegate:self cancelButtonTitle:nil
                              otherButtonTitles:NSLocalizedString(@"ignore", nil), NSLocalizedString(@"cancel", nil), nil] show];
            return;
        }
        else if (protoReq.errorMessage.length > 0 && protoReq.commonName.length > 0 &&
                 ! [self.okIdentity isEqual:protoReq.commonName]) {
            self.request = protoReq;
            self.okIdentity = protoReq.commonName;
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"payee identity isn't certified", nil)
                                        message:protoReq.errorMessage delegate:self cancelButtonTitle:nil
                              otherButtonTitles:NSLocalizedString(@"ignore", nil), NSLocalizedString(@"cancel", nil), nil] show];
            return;
        }
        else if (amount == 0 || amount == UINT64_MAX) {
            BRAmountViewController *c = [self.storyboard instantiateViewControllerWithIdentifier:@"AmountViewController"];
            
            c.delegate = self;
            self.request = protoReq;
            
            if (protoReq.commonName.length > 0) {
                if (valid && ! [protoReq.pkiType isEqual:@"none"]) {
                    c.to = [LOCK @" " stringByAppendingString:sanitizeString(protoReq.commonName)];
                }
                else if (protoReq.errorMessage.length > 0) {
                    c.to = [REDX @" " stringByAppendingString:sanitizeString(protoReq.commonName)];
                }
                else c.to = sanitizeString(protoReq.commonName);
            }
            else c.to = address;
            
            c.navigationItem.title = [NSString stringWithFormat:@"%@ (%@)", [m transferStringForAmount:m.wallet.balance],
                                      [m localCurrencyStringForTransferAmount:m.wallet.balance]];
            [self.navigationController pushViewController:c animated:YES];
            return;
        }
        else if (amount < TX_MIN_OUTPUT_AMOUNT) {
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't make payment", nil)
                                        message:[NSString stringWithFormat:NSLocalizedString(@"transfer payments can't be less than %@", nil),
                                                 [m transferStringForAmount:TX_MIN_OUTPUT_AMOUNT]] delegate:nil
                              cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
            [self cancel:nil];
            return;
        }
        else if (outputTooSmall) {
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't make payment", nil)
                                        message:[NSString stringWithFormat:NSLocalizedString(@"transfer transaction outputs can't be less than %@",
                                                                                             nil), [m transferStringForAmount:TX_MIN_OUTPUT_AMOUNT]]
                                       delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
            [self cancel:nil];
            return;
        }
        
        self.request = protoReq;
        
        if (self.amount == 0) {
            
            if (shapeshift) {
                tx = [m.wallet transactionForAmounts:protoReq.details.outputAmounts
                                     toOutputScripts:protoReq.details.outputScripts withFee:YES toShapeshiftAddress:shapeshift.withdrawalAddress];
                tx.associatedShapeshift = shapeshift;
            } else {
                tx = [m.wallet transactionForAmounts:protoReq.details.outputAmounts
                                     toOutputScripts:protoReq.details.outputScripts withFee:YES];
            }
        }
        else {
            
            if (shapeshift) {
                tx = [m.wallet transactionForAmounts:@[@(self.amount)]
                                     toOutputScripts:@[protoReq.details.outputScripts.firstObject] withFee:YES toShapeshiftAddress:shapeshift.withdrawalAddress];
                tx.associatedShapeshift = shapeshift;
            } else {
                tx = [m.wallet transactionForAmounts:@[@(self.amount)]
                                     toOutputScripts:@[protoReq.details.outputScripts.firstObject] withFee:YES];
            }
        }
        
        if (tx) {
            amount = [m.wallet amountSentByTransaction:tx] - [m.wallet amountReceivedFromTransaction:tx];
            fee = [m.wallet feeForTransaction:tx];
        }
        else {
            fee = [m.wallet feeForTxSize:[m.wallet transactionFor:m.wallet.balance to:address withFee:NO].size];
            amount += fee;
        }
        
        for (NSData *script in protoReq.details.outputScripts) {
            NSString *addr = [NSString addressWithScriptPubKey:script];
            
            if (! addr) addr = NSLocalizedString(@"unrecognized address", nil);
            if ([address rangeOfString:addr].location != NSNotFound) continue;
            address = [address stringByAppendingFormat:@"%@%@", (address.length > 0) ? @", " : @"", addr];
        }
        
        NSString *prompt = [self promptForAmount:amount fee:fee address:address name:protoReq.commonName
                                            memo:protoReq.details.memo isSecure:(valid && ! [protoReq.pkiType isEqual:@"none"])];
        
        // to avoid the frozen pincode keyboard bug, we need to make sure we're scheduled normally on the main runloop
        // rather than a dispatch_async queue
        CFRunLoopPerformBlock([[NSRunLoop mainRunLoop] getCFRunLoop], kCFRunLoopCommonModes, ^{
            [self confirmTransaction:tx withPrompt:prompt forAmount:amount];
        });
        
    } else if ([currency isEqualToString:@"bitcoin"]) {
        BRWalletManager *m = [BRWalletManager sharedInstance];
        BRTransaction *tx = nil;
        
        if (protoReq.errorMessage.length > 0 && protoReq.commonName.length > 0 &&
                 ! [self.okIdentity isEqual:protoReq.commonName]) {
            self.request = protoReq;
            self.okIdentity = protoReq.commonName;
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"payee identity isn't certified", nil)
                                        message:protoReq.errorMessage delegate:self cancelButtonTitle:nil
                              otherButtonTitles:NSLocalizedString(@"ignore", nil), NSLocalizedString(@"cancel", nil), nil] show];
            return;
        }
        else if (amount == 0 || amount == UINT64_MAX) {
            BRAmountViewController *c = [self.storyboard instantiateViewControllerWithIdentifier:@"AmountViewController"];
            c.usingShapeshift = TRUE;
            c.delegate = self;
            self.request = protoReq;
            
            if (protoReq.commonName.length > 0) {
                if (valid && ! [protoReq.pkiType isEqual:@"none"]) {
                    c.to = [LOCK @" " stringByAppendingString:sanitizeString(protoReq.commonName)];
                }
                else if (protoReq.errorMessage.length > 0) {
                    c.to = [REDX @" " stringByAppendingString:sanitizeString(protoReq.commonName)];
                }
                else c.to = sanitizeString(protoReq.commonName);
            }
            else c.to = address;
            
            c.navigationItem.title = [NSString stringWithFormat:@"%@ (%@)", [m transferStringForAmount:m.wallet.balance],
                                      [m localCurrencyStringForTransferAmount:m.wallet.balance]];
            [self.navigationController pushViewController:c animated:YES];
            return;
        }
        else if (amount < TX_MIN_OUTPUT_AMOUNT) {
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't make payment", nil)
                                        message:[NSString stringWithFormat:NSLocalizedString(@"transfer payments can't be less than %@", nil),
                                                 [m transferStringForAmount:TX_MIN_OUTPUT_AMOUNT]] delegate:nil
                              cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
            [self cancel:nil];
            return;
        }
        else if (outputTooSmall) {
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't make payment", nil)
                                        message:[NSString stringWithFormat:NSLocalizedString(@"transfer transaction outputs can't be less than %@",
                                                                                             nil), [m transferStringForAmount:TX_MIN_OUTPUT_AMOUNT]]
                                       delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
            [self cancel:nil];
            return;
        }
        self.request = protoReq;
        [self amountViewController:nil shapeshiftBitcoinAmount:amount approximateTransferAmount:1.03*amount/m.bitcoinTransferPrice];
    }
}

- (void)confirmTransaction:(BRTransaction *)tx withPrompt:(NSString *)prompt forAmount:(uint64_t)amount
{
    BRWalletManager *m = [BRWalletManager sharedInstance];
    
    if (! tx) {
        if (m.didAuthenticate || [m seedWithPrompt:prompt forAmount:amount]) {
            // if user selected an amount equal to or below wallet balance, but the fee will bring the total above the
            // balance, offer to reduce the amount to available funds minus fee
            if ((self.amount <= [m amountForLocalCurrencyString:[m localCurrencyStringForTransferAmount:m.wallet.balance]] ||
                 self.amount <= m.wallet.balance) && self.amount > 0) {
                NSUInteger txSize = [m.wallet transactionForAmounts:@[@(m.wallet.balance)]
                                                    toOutputScripts:@[self.request.details.outputScripts.firstObject] withFee:NO].size,
                cpfpSize = 0;
                
                for (tx in m.wallet.recentTransactions) { // add up size of unconfirmed inputs for child-pays-for-parent
                    if (tx.blockHeight != TX_UNCONFIRMED) break;
                    if ([m.wallet amountSentByTransaction:tx] == 0) cpfpSize += tx.size; // only non-change inputs count
                }
                
                int64_t amount = m.wallet.balance - [m.wallet feeForTxSize:txSize + 34 + cpfpSize];
                
                [[[UIAlertView alloc]
                  initWithTitle:NSLocalizedString(@"insufficient funds for transfer network fee", nil)
                  message:[NSString stringWithFormat:NSLocalizedString(@"reduce payment amount by\n%@ (%@)?", nil),
                           [m transferStringForAmount:self.amount - amount],
                           [m localCurrencyStringForTransferAmount:self.amount - amount]] delegate:self
                  cancelButtonTitle:NSLocalizedString(@"cancel", nil)
                  otherButtonTitles:[NSString stringWithFormat:@"%@ (%@)", [m transferStringForAmount:amount - self.amount],
                                     [m localCurrencyStringForTransferAmount:amount - self.amount]], nil] show];
                self.amount = amount;
            }
            else {
                [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"insufficient funds", nil) message:nil
                                           delegate:self cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
            }
        }
        else [self cancelOrChangeAmount];
        
        return;
    }
    
    if (! [m.wallet signTransaction:tx withPrompt:prompt]) {
        [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't make payment", nil)
                                    message:NSLocalizedString(@"error signing transfer transaction", nil) delegate:nil
                          cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
    }
    
    if (! [tx isSigned]) { // user canceled authentication
        [self cancelOrChangeAmount];
        return;
    }
    
    if (self.navigationController.topViewController != self.parentViewController.parentViewController) {
        [self.navigationController popToRootViewControllerAnimated:YES];
    }
    
    __block BOOL waiting = YES, sent = NO;
    
    [(id)self.parentViewController.parentViewController startActivityWithTimeout:30.0];
    
    [[BRPeerManager sharedInstance] publishTransaction:tx completion:^(NSError *error) {
        if (error) {
            if (! waiting && ! sent) {
                [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't make payment", nil)
                                            message:error.localizedDescription delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil)
                                  otherButtonTitles:nil] show];
                [(id)self.parentViewController.parentViewController stopActivityWithSuccess:NO];
                [self cancel:nil];
            }
        }
        else if (! sent) { //TODO: show full screen sent dialog with tx info, "you sent b10,000 to bob"
            if (tx.associatedShapeshift) {
                [self startObservingShapeshift:tx.associatedShapeshift];

            }
            sent = YES;
            [self.view addSubview:[[[BRBubbleView viewWithText:NSLocalizedString(@"sent!", nil)
                                                        center:CGPointMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2)] popIn]
                                   popOutAfterDelay:2.0]];
            [(id)self.parentViewController.parentViewController stopActivityWithSuccess:YES];
            [self reset:nil];
        }
        
        waiting = NO;
    }];
    
    if (self.request.details.paymentURL.length > 0) {
        uint64_t refundAmount = 0;
        NSMutableData *refundScript = [NSMutableData data];
        
        // use the payment transaction's change address as the refund address, which prevents the same address being
        // used in other transactions in the event no refund is ever issued
        [refundScript appendScriptPubKeyForAddress:m.wallet.changeAddress];
        for (NSNumber *amt in self.request.details.outputAmounts) refundAmount += [amt unsignedLongLongValue];
        
        // TODO: keep track of commonName/memo to associate them with outputScripts
        BRPaymentProtocolPayment *payment =
        [[BRPaymentProtocolPayment alloc] initWithMerchantData:self.request.details.merchantData
                                                  transactions:@[tx] refundToAmounts:@[@(refundAmount)] refundToScripts:@[refundScript] memo:nil];
        
        NSLog(@"posting payment to: %@", self.request.details.paymentURL);
        
        [BRPaymentRequest postPayment:payment type:@"transfer" to:self.request.details.paymentURL timeout:20.0
                           completion:^(BRPaymentProtocolACK *ack, NSError *error) {
                               [(id)self.parentViewController.parentViewController stopActivityWithSuccess:(! error)];
                               
                               if (error) {
                                   if (! waiting && ! sent) {
                                       [[[UIAlertView alloc] initWithTitle:@"" message:error.localizedDescription delegate:nil
                                                         cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
                                       [(id)self.parentViewController.parentViewController stopActivityWithSuccess:NO];
                                       [self cancel:nil];
                                   }
                               }
                               else if (! sent) {
                                   sent = YES;
                                   tx.timestamp = [NSDate timeIntervalSinceReferenceDate];
                                   [m.wallet registerTransaction:tx];
                                   [self.view
                                    addSubview:[[[BRBubbleView
                                                  viewWithText:(ack.memo.length > 0 ? ack.memo : NSLocalizedString(@"sent!", nil))
                                                  center:CGPointMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2)] popIn]
                                                popOutAfterDelay:(ack.memo.length > 0 ? 3.0 : 2.0)]];
                                   [(id)self.parentViewController.parentViewController stopActivityWithSuccess:YES];
                                   [self reset:nil];
                               }
                               
                               waiting = NO;
                           }];
    }
    else waiting = NO;
}

- (void)confirmSweep:(NSString *)privKey
{
    if (! [privKey isValidDigitalCashPrivateKey] && ! [privKey isValidDigitalCashBIP38Key]) return;
    
    BRWalletManager *m = [BRWalletManager sharedInstance];
    BRBubbleView *v = [BRBubbleView viewWithText:NSLocalizedString(@"checking private key balance...", nil)
                                          center:CGPointMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2)];
    
    v.font = [UIFont fontWithName:@"HelveticaNeue" size:15.0];
    v.customView = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhite];
    [(id)v.customView startAnimating];
    [self.view addSubview:[v popIn]];
    
    [m sweepPrivateKey:privKey withFee:YES completion:^(BRTransaction *tx, uint64_t fee, NSError *error) {
        [v popOut];
        
        if (error) {
            [[[UIAlertView alloc] initWithTitle:@"" message:error.localizedDescription delegate:self
                              cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
            [self cancel:nil];
        }
        else if (tx) {
            uint64_t amount = fee;
            
            for (NSNumber *amt in tx.outputAmounts) amount += amt.unsignedLongLongValue;
            self.sweepTx = tx;
            
            [[[UIAlertView alloc] initWithTitle:@"" message:[NSString
                                                             stringWithFormat:NSLocalizedString(@"Send %@ (%@) from this private key into your wallet? "
                                                                                                "The transfer network will receive a fee of %@ (%@).", nil),
                                                             [m transferStringForAmount:amount], [m localCurrencyStringForTransferAmount:amount], [m transferStringForAmount:fee],
                                                             [m localCurrencyStringForTransferAmount:fee]] delegate:self cancelButtonTitle:NSLocalizedString(@"cancel", nil)
                              otherButtonTitles:[NSString stringWithFormat:@"%@ (%@)", [m transferStringForAmount:amount],
                                                 [m localCurrencyStringForTransferAmount:amount]], nil] show];
        }
        else [self cancel:nil];
    }];
}

- (void)showBalance:(NSString *)address
{
    if (! [address isValidDigitalCashAddress]) return;
    
    BRWalletManager *m = [BRWalletManager sharedInstance];
    BRBubbleView *v = [BRBubbleView viewWithText:NSLocalizedString(@"checking address balance...", nil)
                                          center:CGPointMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2)];
    
    v.font = [UIFont fontWithName:@"HelveticaNeue" size:15.0];
    v.customView = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhite];
    [(id)v.customView startAnimating];
    [self.view addSubview:[v popIn]];
    
    [m utxosForAddress:address completion:^(NSArray *utxos, NSArray *amounts, NSArray *scripts, NSError *error) {
        [v popOut];
        
        if (error) {
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't check address balance", nil)
                                        message:error.localizedDescription delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil)
                              otherButtonTitles:nil] show];
        }
        else {
            uint64_t balance = 0;
            
            for (NSNumber *amt in amounts) balance += [amt unsignedLongLongValue];
            
            [[[UIAlertView alloc] initWithTitle:@""
                                        message:[NSString stringWithFormat:NSLocalizedString(@"%@\n\nbalance: %@ (%@)", nil), address,
                                                 [m transferStringForAmount:balance], [m localCurrencyStringForTransferAmount:balance]] delegate:nil
                              cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
        }
    }];
}

- (void)cancelOrChangeAmount
{
    if (self.canChangeAmount && self.request && self.amount == 0) {
        [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"change payment amount?", nil)
                                    message:nil delegate:self cancelButtonTitle:NSLocalizedString(@"cancel", nil)
                          otherButtonTitles:NSLocalizedString(@"change", nil), nil] show];
        self.amount = UINT64_MAX;
    }
    else [self cancel:nil];
}

- (void)hideTips
{
    if (self.tipView.alpha > 0.5) [self.tipView popOut];
}

- (BOOL)nextTip
{
    [self.clipboardText resignFirstResponder];
    if (self.tipView.alpha < 0.5) return [(id)self.parentViewController.parentViewController nextTip];
    
    BRBubbleView *v = self.tipView;
    
    self.tipView = nil;
    [v popOut];
    
    if ([v.text hasPrefix:SCAN_TIP]) {
        self.tipView = [BRBubbleView viewWithText:CLIPBOARD_TIP
                                         tipPoint:CGPointMake(self.clipboardButton.center.x, self.clipboardButton.center.y + 10.0)
                                     tipDirection:BRBubbleTipDirectionUp];
        self.tipView.backgroundColor = v.backgroundColor;
        self.tipView.font = v.font;
        self.tipView.userInteractionEnabled = NO;
        [self.view addSubview:[self.tipView popIn]];
    }
    else if (self.showTips && [v.text hasPrefix:CLIPBOARD_TIP]) {
        self.showTips = NO;
        [(id)self.parentViewController.parentViewController tip:self];
    }
    
    return YES;
}

- (void)resetQRGuide
{
    self.scanController.message.text = nil;
    self.scanController.cameraGuide.image = [UIImage imageNamed:@"cameraguide"];
}

- (void)updateClipboardText
{
    NSString *p = [[[UIPasteboard generalPasteboard] string]
                   stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    UIImage *img = [[UIPasteboard generalPasteboard] image];
    NSMutableArray *a = [NSMutableArray array];
    NSCharacterSet *c = [[NSCharacterSet alphanumericCharacterSet] invertedSet];
    
    if (p) {
        [a addObject:p];
        [a addObjectsFromArray:[p componentsSeparatedByCharactersInSet:c]];
    }
    
    if (img && CIDetectorTypeQRCode) {
        for (CIQRCodeFeature *qr in [[CIDetector detectorOfType:CIDetectorTypeQRCode context:nil options:nil]
                                     featuresInImage:[CIImage imageWithCGImage:img.CGImage]]) {
            [a addObject:[qr.messageString
                          stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]];
        }
    }
    
    self.clipboardText.text = @"";
    
    for (NSString *s in a) {
        BRPaymentRequest *req = [BRPaymentRequest requestWithString:s];
        
        if ([req.paymentAddress isValidDigitalCashAddress]) {
            self.clipboardText.text = (req.label.length > 0) ? sanitizeString(req.label) : req.paymentAddress;
            break;
        }
        else if ([req.paymentAddress isValidBitcoinAddress]) {
            self.clipboardText.text = (req.label.length > 0) ? sanitizeString(req.label) : req.paymentAddress;
            break;
        }
        else if ([s hasPrefix:@"bitcoin:"] || [s hasPrefix:@"transfer:"]) {
            self.clipboardText.text = sanitizeString(s);
            break;
        }
    }
    
    CGFloat w = [self.clipboardText.text sizeWithAttributes:@{NSFontAttributeName:self.clipboardText.font}].width + 12;
    
    if (w < self.clipboardButton.bounds.size.width ) w = self.clipboardButton.bounds.size.width;
    if (w > self.view.bounds.size.width - 16.0) w = self.view.bounds.size.width - 16.0;
    self.clipboardXLeft.constant = (self.view.bounds.size.width - w)/2.0;
    [self.clipboardText scrollRangeToVisible:NSMakeRange(0, 0)];
}

#pragma mark - Shapeshift

-(void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context {
    DCShapeshiftEntity * shapeshift = (DCShapeshiftEntity *)object;
    switch ([shapeshift.shapeshiftStatus integerValue]) {
        case eShapeshiftAddressStatus_Complete:
        {
            NSArray * shapeshiftsInProgress = [DCShapeshiftEntity shapeshiftsInProgress];
            if (![shapeshiftsInProgress count]) {
                self.shapeshiftLabel.text = shapeshift.shapeshiftStatusString;
                self.shapeshiftView.hidden = TRUE;
            }
            [self.view addSubview:[[[BRBubbleView viewWithText:NSLocalizedString(@"shapeshift succeeded", nil)
                                                        center:CGPointMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2)] popIn]
                                   popOutAfterDelay:2.0]];
            break;
        }
        case eShapeshiftAddressStatus_Received:
            self.shapeshiftLabel.text = shapeshift.shapeshiftStatusString;
        default:
            break;
    }
}

-(void)startObservingShapeshift:(DCShapeshiftEntity*)shapeshift {
    
        [shapeshift addObserver:self forKeyPath:@"shapeshiftStatus" options:NSKeyValueObservingOptionNew context:nil];
        [shapeshift routinelyCheckStatusAtInterval:10];
        self.shapeshiftView.hidden = FALSE;
}


#pragma mark - IBAction

- (IBAction)tip:(id)sender
{
    if ([self nextTip]) return;
    
    if (! [sender isKindOfClass:[UIGestureRecognizer class]] || ! [[sender view] isKindOfClass:[UILabel class]]) {
        if (! [sender isKindOfClass:[UIViewController class]]) return;
        self.showTips = YES;
    }
    
    self.tipView = [BRBubbleView viewWithText:SCAN_TIP
                                     tipPoint:CGPointMake(self.scanButton.center.x, self.scanButton.center.y - 10.0)
                                 tipDirection:BRBubbleTipDirectionDown];
    self.tipView.backgroundColor = [UIColor lightGrayColor];
    self.tipView.font = [UIFont fontWithName:@"HelveticaNeue" size:15.0];
    [self.view addSubview:[self.tipView popIn]];
}

- (IBAction)scanQR:(id)sender
{
    if ([self nextTip]) return;
    if (! [sender isEqual:self.scanButton]) self.showBalance = YES;
    [sender setEnabled:NO];
    self.scanController.delegate = self;
    self.scanController.transitioningDelegate = self;
    [self.navigationController presentViewController:self.scanController animated:YES completion:nil];
}

- (IBAction)payToClipboard:(id)sender
{
    if ([self nextTip]) return;
    
    BRWalletManager *m = [BRWalletManager sharedInstance];
    NSString *p = [[[UIPasteboard generalPasteboard] string]
                   stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    UIImage *img = [[UIPasteboard generalPasteboard] image];
    NSMutableArray *a = [NSMutableArray array];
    NSCharacterSet *c = [[NSCharacterSet alphanumericCharacterSet] invertedSet];
    
    if (p) {
        [a addObject:p];
        [a addObjectsFromArray:[p componentsSeparatedByCharactersInSet:c]];
    }
    
    if (img && CIDetectorTypeQRCode) {
        for (CIQRCodeFeature *qr in [[CIDetector detectorOfType:CIDetectorTypeQRCode context:nil options:nil]
                                     featuresInImage:[CIImage imageWithCGImage:img.CGImage]]) {
            [a addObject:[qr.messageString
                                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]];
        }
    }
    
    [sender setEnabled:NO];
    self.clearClipboard = YES;
    
    for (NSString *s in a) {
        BRPaymentRequest *req = [BRPaymentRequest requestWithString:s];
        NSData *d = s.hexToData.reverse;
        
        // if the clipboard contains a known txHash, we know it's not a hex encoded private key
        if (d.length == 32 && [[m.wallet.recentTransactions valueForKey:@"txHash"] containsObject:d]) continue;
        
        if ([req.paymentAddress isValidBitcoinAddress] || [req.paymentAddress isValidDigitalCashAddress] || [s isValidBitcoinPrivateKey] || [s isValidDigitalCashPrivateKey] || [s isValidBitcoinBIP38Key] || [s isValidDigitalCashBIP38Key] ||
            (req.r.length > 0 && ([s hasPrefix:@"bitcoin:"] || [s hasPrefix:@"transfer:"]))) {
            [self performSelector:@selector(confirmRequest:) withObject:req afterDelay:0.1];// delayed to show highlight
            return;
        } else if (req.r.length > 0) {
            [BRPaymentRequest fetch:req.r type:req.type timeout:5.0 completion:^(BRPaymentProtocolRequest *req, NSError *error) {
                if (error) {
                    [[[UIAlertView alloc] initWithTitle:@""
                                                message:NSLocalizedString(@"clipboard doesn't contain a valid Transfer or Bitcoin address", nil) delegate:nil
                                      cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
                    [self performSelector:@selector(cancel:) withObject:self afterDelay:0.1];
                }
                else [self confirmProtocolRequest:req];
            }];
            
            return;
        }
    }
    
    [[[UIAlertView alloc] initWithTitle:@""
                                message:NSLocalizedString(@"clipboard doesn't contain a valid Transfer or Bitcoin address", nil) delegate:nil
                      cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
    [self performSelector:@selector(cancel:) withObject:self afterDelay:0.1];
}

- (IBAction)reset:(id)sender
{
    if (self.navigationController.topViewController != self.parentViewController.parentViewController) {
        [self.navigationController popToRootViewControllerAnimated:YES];
    }
    
    if (self.clearClipboard) [[UIPasteboard generalPasteboard] setString:@""];
    self.request = nil;
    [self cancel:sender];
}

- (IBAction)cancel:(id)sender
{
    self.url = nil;
    self.sweepTx = nil;
    self.amount = 0;
    self.okAddress = self.okIdentity = nil;
    self.clearClipboard = self.useClipboard = NO;
    self.canChangeAmount = self.showBalance = NO;
    self.scanButton.enabled = self.clipboardButton.enabled = YES;
    [self updateClipboardText];
}

#pragma mark - BRAmountViewControllerDelegate

- (void)amountViewController:(BRAmountViewController *)amountViewController selectedAmount:(uint64_t)amount
{
    self.amount = amount;
    [self confirmProtocolRequest:self.request];
}

-(void)verifyShapeshiftAmountIsInBounds:(uint64_t)amount completionBlock:(void (^)())completionBlock failureBlock:(void (^)())failureBlock {
    [[DCShapeshiftManager sharedInstance] GET_marketInfo:^(NSDictionary *marketInfo, NSError *error) {
        if (error) {
            failureBlock();
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Shapeshift failed", nil)
                                        message:error.localizedDescription
                                       delegate:self cancelButtonTitle:NSLocalizedString(@"ok", nil)
                              otherButtonTitles:nil] show];
        } else {
            BRWalletManager *m = [BRWalletManager sharedInstance];
            if ([DCShapeshiftManager sharedInstance].min > (amount * .97)) {
                failureBlock();
                [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Shapeshift failed", nil)
                                            message:[NSString stringWithFormat:NSLocalizedString(@"The amount you wanted to shapeshift is too low, "
                                                                                                 @"please input a value over %@", nil),[m transferStringForAmount:[DCShapeshiftManager sharedInstance].min / .97]]
                                           delegate:self cancelButtonTitle:NSLocalizedString(@"ok", nil)
                                  otherButtonTitles:nil] show];
                return;
            } else if ([DCShapeshiftManager sharedInstance].limit < (amount * 1.03)) {
                failureBlock();
                [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Shapeshift failed", nil)
                                            message:[NSString stringWithFormat:NSLocalizedString(@"The amount you wanted to shapeshift is too high, "
                                                                                                 @"please input a value under %@", nil),[m transferStringForAmount:[DCShapeshiftManager sharedInstance].limit / 1.03]]
                                           delegate:self cancelButtonTitle:NSLocalizedString(@"ok", nil)
                                  otherButtonTitles:nil] show];
                return;
            }
            completionBlock();
        }
    }];

}

- (void)amountViewController:(BRAmountViewController *)amountViewController shapeshiftBitcoinAmount:(uint64_t)amount approximateTransferAmount:(uint64_t)transferAmount
{
    MBProgressHUD *hud  = [MBProgressHUD showHUDAddedTo:self.navigationController.topViewController.view animated:YES];
    hud.labelText       = NSLocalizedString(@"Starting Shapeshift!", nil);
    
    [self verifyShapeshiftAmountIsInBounds:transferAmount completionBlock:^{
        //we know the exact amount of bitcoins we want to send
        BRWalletManager *m = [BRWalletManager sharedInstance];
        NSString * address = [NSString bitcoinAddressWithScriptPubKey:self.request.details.outputScripts.firstObject];
        NSString * returnAddress = m.wallet.receiveAddress;
        NSNumber * numberAmount = [m numberForAmount:amount];
        [[DCShapeshiftManager sharedInstance] POST_SendAmount:numberAmount withAddress:address returnAddress:returnAddress completionBlock:^(NSDictionary *shiftInfo, NSError *error) {
            [hud hide:TRUE];
            if (error) {
                NSLog(@"shapeshiftBitcoinAmount Error %@",error);
                [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Shapeshift failed", nil)
                                            message:error.localizedDescription
                                           delegate:self cancelButtonTitle:NSLocalizedString(@"ok", nil)
                                  otherButtonTitles:nil] show];
                return;
            }
            NSString * depositAddress = shiftInfo[@"deposit"];
            NSString * withdrawalAddress = shiftInfo[@"withdrawal"];
            NSNumber * withdrawalAmount = shiftInfo[@"withdrawalAmount"];
            NSNumber * depositAmountNumber = @([shiftInfo[@"depositAmount"] doubleValue]);
            if (depositAmountNumber && [withdrawalAmount floatValue] && [depositAmountNumber floatValue]) {
                uint64_t depositAmount = [[[NSDecimalNumber decimalNumberWithString:[NSString stringWithFormat:@"%@",depositAmountNumber]] decimalNumberByMultiplyingByPowerOf10:8]
                                          unsignedLongLongValue];
                self.amount = depositAmount;
                
                DCShapeshiftEntity * shapeshift = [DCShapeshiftEntity registerShapeshiftWithInputAddress:depositAddress andWithdrawalAddress:withdrawalAddress withStatus:eShapeshiftAddressStatus_Unused fixedAmountOut:depositAmountNumber amountIn:depositAmountNumber];
                
                BRPaymentRequest * request = [BRPaymentRequest requestWithString:[NSString stringWithFormat:@"transfer:%@?amount=%llu&label=%@&message=Shapeshift to %@",depositAddress,depositAmount,sanitizeString(self.request.commonName),withdrawalAddress]];
                [self confirmProtocolRequest:request.protocolRequest currency:@"transfer" associatedShapeshift:shapeshift];
            }
        }];
    } failureBlock:^{
        [hud hide:TRUE];
    }];
}

- (void)amountViewController:(BRAmountViewController *)amountViewController shapeshiftTransferAmount:(uint64_t)amount
{
    MBProgressHUD *hud  = [MBProgressHUD showHUDAddedTo:self.navigationController.topViewController.view animated:YES];
    hud.labelText       = NSLocalizedString(@"Starting Shapeshift!", nil);
    [self verifyShapeshiftAmountIsInBounds:amount completionBlock:^{
        //we don't know the exact amount of bitcoins we want to send, we are just sending transfer
        BRWalletManager *m = [BRWalletManager sharedInstance];
        NSString * address = [NSString bitcoinAddressWithScriptPubKey:self.request.details.outputScripts.firstObject];
        NSString * returnAddress = m.wallet.receiveAddress;
        self.amount = amount;
        DCShapeshiftEntity * shapeshift = [DCShapeshiftEntity shapeshiftHavingWithdrawalAddress:address];
        NSString * depositAddress = shapeshift.inputAddress;

        if (shapeshift) {
            [hud hide:TRUE];
                        BRPaymentRequest * request = [BRPaymentRequest requestWithString:[NSString stringWithFormat:@"transfer:%@?amount=%llu&label=%@&message=Shapeshift to %@",depositAddress,self.amount,sanitizeString(self.request.commonName),address]];
            [self confirmProtocolRequest:request.protocolRequest currency:@"transfer" associatedShapeshift:shapeshift];
        } else {
            [[DCShapeshiftManager sharedInstance] POST_ShiftWithAddress:address returnAddress:returnAddress completionBlock:^(NSDictionary *shiftInfo, NSError *error) {
                [hud hide:TRUE];
                if (error) {
                    NSLog(@"shapeshiftTransferAmount Error %@",error);
                    [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Shapeshift failed", nil)
                                                message:error.localizedDescription
                                               delegate:self cancelButtonTitle:NSLocalizedString(@"ok", nil)
                                      otherButtonTitles:nil] show];
                    return;
                }
                NSString * depositAddress = shiftInfo[@"deposit"];
                NSString * withdrawalAddress = shiftInfo[@"withdrawal"];
                if (withdrawalAddress && depositAddress) {
                    DCShapeshiftEntity * shapeshift = [DCShapeshiftEntity registerShapeshiftWithInputAddress:depositAddress andWithdrawalAddress:withdrawalAddress withStatus:eShapeshiftAddressStatus_Unused];
                    BRPaymentRequest * request = [BRPaymentRequest requestWithString:[NSString stringWithFormat:@"transfer:%@?amount=%llu&label=%@&message=Shapeshift to %@",depositAddress,self.amount,sanitizeString(self.request.commonName),withdrawalAddress]];
                    [self confirmProtocolRequest:request.protocolRequest currency:@"transfer" associatedShapeshift:shapeshift];
                }
            }];
        }
    } failureBlock:^{
        [hud hide:TRUE];
    }];
}

#pragma mark - AVCaptureMetadataOutputObjectsDelegate

- (void)captureOutput:(AVCaptureOutput *)captureOutput didOutputMetadataObjects:(NSArray *)metadataObjects
       fromConnection:(AVCaptureConnection *)connection
{
    for (AVMetadataMachineReadableCodeObject *o in metadataObjects) {
        if (! [o.type isEqual:AVMetadataObjectTypeQRCode]) continue;
        
        NSString *s = [o.stringValue stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        BRPaymentRequest *request = [BRPaymentRequest requestWithString:s];
        
        
        if ((![request isValid] && ![s isValidDigitalCashPrivateKey] && ![s isValidDigitalCashBIP38Key]) ||
                        (request.r.length > 0 && !([s hasPrefix:@"bitcoin:"] || [s hasPrefix:@"transfer:"]))) {
            [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(resetQRGuide) object:nil];
            self.scanController.cameraGuide.image = [UIImage imageNamed:@"cameraguide-red"];
            [BRPaymentRequest fetch:request.r type:request.type timeout:5.0
                         completion:^(BRPaymentProtocolRequest *req, NSError *error) {
                             dispatch_async(dispatch_get_main_queue(), ^{
                                 [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(resetQRGuide) object:nil];
                                 
                                 if (req) {
                                     self.scanController.cameraGuide.image = [UIImage imageNamed:@"cameraguide-green"];
                                    [self.scanController stop];
                                     [self.navigationController dismissViewControllerAnimated:YES completion:^{
                                         [self resetQRGuide];
                                     }];
                                     
                                     [self confirmProtocolRequest:req];
                                 }
                                 else {
                                     self.scanController.cameraGuide.image = [UIImage imageNamed:@"cameraguide-red"];
                                     
                                     if (([s hasPrefix:@"transfer:"] && request.paymentAddress.length > 1) || [request.paymentAddress hasPrefix:@"X"] ||
                                         [request.paymentAddress hasPrefix:@"Y"]) {
                                         self.scanController.message.text = [NSString stringWithFormat:@"%@\n%@",
                                                                             NSLocalizedString(@"not a valid transfer address", nil),
                                                                             request.paymentAddress];
                                     } else if (([s hasPrefix:@"bitcoin:"] && request.paymentAddress.length > 1) || [request.paymentAddress hasPrefix:@"1"] ||
                                                   [request.paymentAddress hasPrefix:@"3"]) {
                                         self.scanController.message.text = [NSString stringWithFormat:@"%@\n%@",
                                                                             NSLocalizedString(@"not a valid bitcoin address", nil),
                                                                             request.paymentAddress];
                                     }
                                     else self.scanController.message.text = NSLocalizedString(@"not a transfer or bitcoin QR code", nil);
                                     
                                     [self performSelector:@selector(resetQRGuide) withObject:nil afterDelay:0.35];
                                 }
                             });
                         }];
        }
        else {
            self.scanController.cameraGuide.image = [UIImage imageNamed:@"cameraguide-green"];
            [self.scanController stop];
            
            if (request.r.length > 0) { // start fetching payment protocol request right away
                [BRPaymentRequest fetch:request.r type:request.type timeout:5.0
                             completion:^(BRPaymentProtocolRequest *req, NSError *error) {
                                 if (error) request.r = nil;
                                 
                                 if (error && ! [request isValid]) {
                                     [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't make payment", nil)
                                                                 message:error.localizedDescription delegate:nil
                                                       cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
                                     [self cancel:nil];
                                 }
                                 
                                 dispatch_async(dispatch_get_main_queue(), ^{
                                     [self.navigationController dismissViewControllerAnimated:YES completion:^{
                                         [self resetQRGuide];
                                     }];
                                     
                                     if (error) {
                                         [self confirmRequest:request];
                                     }
                                     else [self confirmProtocolRequest:req];
                                 });
                             }];
            }
            else {
                [self.navigationController dismissViewControllerAnimated:YES completion:^{
                    [self resetQRGuide];
                    if (request.amount > 0) self.canChangeAmount = YES;
                }];
                
                if (self.showBalance) {
                    [self showBalance:request.paymentAddress];
                    [self cancel:nil];
                }
                else [self confirmRequest:request];
            }
        }
        
        break;
    }
}

#pragma mark - UIAlertViewDelegate

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
    NSString *title = [alertView buttonTitleAtIndex:buttonIndex];
    
    if (buttonIndex == alertView.cancelButtonIndex || [title isEqual:NSLocalizedString(@"cancel", nil)]) {
        if (self.url) {
            self.clearClipboard = YES;
            [self handleURL:self.url];
        }
        else [self cancelOrChangeAmount];
    }
    else if (self.sweepTx) {
        [(id)self.parentViewController.parentViewController startActivityWithTimeout:30];
        
        [[BRPeerManager sharedInstance] publishTransaction:self.sweepTx completion:^(NSError *error) {
            [(id)self.parentViewController.parentViewController stopActivityWithSuccess:(! error)];
            
            if (error) {
                [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"couldn't sweep balance", nil)
                                            message:error.localizedDescription delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil)
                                  otherButtonTitles:nil] show];
                [self cancel:nil];
                return;
            }
            
            [self.view addSubview:[[[BRBubbleView viewWithText:NSLocalizedString(@"swept!", nil)
                                                        center:CGPointMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2)]
                                    popIn] popOutAfterDelay:2.0]];
            [self reset:nil];
        }];
    }
    else if (self.request) {
        [self confirmProtocolRequest:self.request];
    }
    else if (self.url) [self handleURL:self.url];
}

#pragma mark UITextViewDelegate

- (BOOL)textViewShouldBeginEditing:(UITextView *)textView
{
    if ([self nextTip]) return NO;
    return YES;
}

- (void)textViewDidBeginEditing:(UITextView *)textView
{
    //BUG: XXX this needs to take keyboard size into account
    self.useClipboard = NO;
    self.clipboardText.text = [[UIPasteboard generalPasteboard] string];
    [textView scrollRangeToVisible:textView.selectedRange];
    
    [UIView animateWithDuration:0.35 delay:0.0 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.view.center = CGPointMake(self.view.center.x, self.view.bounds.size.height/2.0 - 100.0);
        self.sendLabel.alpha = 0.0;
    } completion:nil];
}

- (void)textViewDidEndEditing:(UITextView *)textView
{
    [UIView animateWithDuration:0.35 delay:0.0 options:UIViewAnimationOptionCurveEaseOut animations:^{
        self.view.center = CGPointMake(self.view.center.x, self.view.bounds.size.height/2.0);
        self.sendLabel.alpha = 1.0;
    } completion:nil];
    
    if (! self.useClipboard) [[UIPasteboard generalPasteboard] setString:textView.text];
    [self updateClipboardText];
}

- (BOOL)textView:(UITextView *)textView shouldChangeTextInRange:(NSRange)range replacementText:(NSString *)text
{
    if ([text isEqual:@"\n"]) {
        [textView resignFirstResponder];
        return NO;
    }
    
    if (text.length > 0 || range.length > 0) self.useClipboard = NO;
    return YES;
}

#pragma mark UIViewControllerAnimatedTransitioning

// This is used for percent driven interactive transitions, as well as for container controllers that have companion
// animations that might need to synchronize with the main animation.
- (NSTimeInterval)transitionDuration:(id<UIViewControllerContextTransitioning>)transitionContext
{
    return 0.35;
}

// This method can only be a nop if the transition is interactive and not a percentDriven interactive transition.
- (void)animateTransition:(id<UIViewControllerContextTransitioning>)transitionContext
{
    UIView *v = transitionContext.containerView;
    UIViewController *to = [transitionContext viewControllerForKey:UITransitionContextToViewControllerKey],
    *from = [transitionContext viewControllerForKey:UITransitionContextFromViewControllerKey];
    UIImageView *img = self.scanButton.imageView;
    UIView *guide = self.scanController.cameraGuide;
    
    [self.scanController.view layoutIfNeeded];
    
    if (to == self.scanController) {
        [v addSubview:to.view];
        to.view.frame = from.view.frame;
        to.view.center = CGPointMake(to.view.center.x, v.frame.size.height*3/2);
        guide.transform = CGAffineTransformMakeScale(img.bounds.size.width/guide.bounds.size.width,
                                                     img.bounds.size.height/guide.bounds.size.height);
        guide.alpha = 0;
        
        [UIView animateWithDuration:0.1 animations:^{
            img.alpha = 0.0;
            guide.alpha = 1.0;
        }];
        
        [UIView animateWithDuration:[self transitionDuration:transitionContext] delay:0 usingSpringWithDamping:0.8
              initialSpringVelocity:0 options:UIViewAnimationOptionCurveEaseIn animations:^{
                  to.view.center = from.view.center;
              } completion:^(BOOL finished) {
                  img.alpha = 1.0;
                  [transitionContext completeTransition:YES];
              }];
        
        [UIView animateWithDuration:0.8 delay:0.15 usingSpringWithDamping:0.5 initialSpringVelocity:0
                            options:UIViewAnimationOptionCurveEaseOut animations:^{
                                guide.transform = CGAffineTransformIdentity;
                            } completion:^(BOOL finished) {
                                [to.view addSubview:guide];
                            }];
    }
    else {
        [v insertSubview:to.view belowSubview:from.view];
        [self cancel:nil];
        
        [UIView animateWithDuration:0.8 delay:0.0 usingSpringWithDamping:0.5 initialSpringVelocity:0
                            options:UIViewAnimationOptionCurveEaseIn animations:^{
                                guide.transform = CGAffineTransformMakeScale(img.bounds.size.width/guide.bounds.size.width,
                                                                             img.bounds.size.height/guide.bounds.size.height);
                                guide.alpha = 0.0;
                            } completion:^(BOOL finished) {
                                guide.transform = CGAffineTransformIdentity;
                                guide.alpha = 1.0;
                            }];
        
        [UIView animateWithDuration:[self transitionDuration:transitionContext] - 0.15 delay:0.15
                            options:UIViewAnimationOptionCurveEaseIn animations:^{
                                from.view.center = CGPointMake(from.view.center.x, v.frame.size.height*3/2);
                            } completion:^(BOOL finished) {
                                [transitionContext completeTransition:YES];
                            }];
    }
}

#pragma mark - UIViewControllerTransitioningDelegate

- (id<UIViewControllerAnimatedTransitioning>)animationControllerForPresentedController:(UIViewController *)presented
                                                                  presentingController:(UIViewController *)presenting sourceController:(UIViewController *)source
{
    return self;
}

- (id<UIViewControllerAnimatedTransitioning>)animationControllerForDismissedController:(UIViewController *)dismissed
{
    return self;
}

@end
