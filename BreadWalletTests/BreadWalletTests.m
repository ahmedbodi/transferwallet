//
//  TransferWalletTests.m
//  TransferWalletTests
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

#import "TransferWalletTests.h"
#import "BRWalletManager.h"
#import "BRBIP32Sequence.h"
#import "BRBIP39Mnemonic.h"
#import "BRTransaction.h"
#import "BRKey.h"
#import "BRKey+BIP38.h"
#import "BRMerkleBlock.h"
#import "BRPaymentRequest.h"
#import "BRPaymentProtocol.h"
#import "NSData+Transfer.h"
#import "NSMutableData+Bitcoin.h"
#import "NSString+Transfer.h"
#import "NSData+Blake.h"
#import "NSData+Bmw.h"
#import "NSData+CubeHash.h"
#import "NSData+Echo.h"
#import "NSData+Keccak.h"

#define SKIP_BIP38 1

@implementation TransferWalletTests

- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
}

- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}

#pragma mark - testBase58

- (void)testBase58
{
    // test bad input
    NSString *s = [NSString base58WithData:[BTC @"#&$@*^(*#!^" base58ToData]];

    XCTAssertTrue(s.length == 0, @"[NSString base58WithData:]");
    
    s = [NSString base58WithData:[@"" base58ToData]];
    XCTAssertEqualObjects(@"", s, @"[NSString base58WithData:]");

    s = [NSString base58WithData:[@"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" base58ToData]];
    XCTAssertEqualObjects(@"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", s,
                          @"[NSString base58WithData:]");

    s = [NSString base58WithData:[@"1111111111111111111111111111111111111111111111111111111111111111111" base58ToData]];
    XCTAssertEqualObjects(@"1111111111111111111111111111111111111111111111111111111111111111111", s,
                          @"[NSString base58WithData:]");
    
    s = [NSString base58WithData:[@"111111111111111111111111111111111111111111111111111111111111111111z" base58ToData]];
    XCTAssertEqualObjects(@"111111111111111111111111111111111111111111111111111111111111111111z", s,
                          @"[NSString base58WithData:]");

    s = [NSString base58WithData:[@"z" base58ToData]];
    XCTAssertEqualObjects(@"z", s, @"[NSString base58WithData:]");
    
    s = [NSString base58checkWithData:nil];
    XCTAssertTrue(s == nil, @"[NSString base58checkWithData:]");

    s = [NSString base58checkWithData:@"".hexToData];
    XCTAssertEqualObjects([NSData data], [s base58checkToData], @"[NSString base58checkWithData:]");

    s = [NSString base58checkWithData:@"000000000000000000000000000000000000000000".hexToData];
    XCTAssertEqualObjects(@"000000000000000000000000000000000000000000".hexToData, [s base58checkToData],
                          @"[NSString base58checkWithData:]");

    s = [NSString base58checkWithData:@"000000000000000000000000000000000000000001".hexToData];
    XCTAssertEqualObjects(@"000000000000000000000000000000000000000001".hexToData, [s base58checkToData],
                          @"[NSString base58checkWithData:]");

    s = [NSString base58checkWithData:@"05FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".hexToData];
    XCTAssertEqualObjects(@"05FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".hexToData, [s base58checkToData],
                          @"[NSString base58checkWithData:]");
}

#pragma mark - testRMD160

- (void)testRMD160
{
    NSData *d = [@"Free online RIPEMD160 Calculator, type text here..." dataUsingEncoding:NSUTF8StringEncoding].RMD160;
    
    XCTAssertEqualObjects(@"9501a56fb829132b8748f0ccc491f0ecbc7f945b".hexToData, d, @"[NSData RMD160]");
    
    d = [@"this is some text to test the ripemd160 implementation with more than 64bytes of data since it's internal "
         "digest buffer is 64bytes in size" dataUsingEncoding:NSUTF8StringEncoding].RMD160;
    XCTAssertEqualObjects(@"4402eff42157106a5d92e4d946185856fbc50e09".hexToData, d, @"[NSData RMD160]");

    d = [@"123456789012345678901234567890123456789012345678901234567890"
         dataUsingEncoding:NSUTF8StringEncoding].RMD160;
    XCTAssertEqualObjects(@"00263b999714e756fa5d02814b842a2634dd31ac".hexToData, d, @"[NSData RMD160]");

    d = [@"1234567890123456789012345678901234567890123456789012345678901234"
         dataUsingEncoding:NSUTF8StringEncoding].RMD160; // a message exactly 64bytes long (internal buffer size)
    XCTAssertEqualObjects(@"fa8c1a78eb763bb97d5ea14ce9303d1ce2f33454".hexToData, d, @"[NSData RMD160]");

    d = [NSData data].RMD160; // empty
    XCTAssertEqualObjects(@"9c1185a5c5e9fc54612808977ee8f548b2258d31".hexToData, d, @"[NSData RMD160]");
    
    d = [@"a" dataUsingEncoding:NSUTF8StringEncoding].RMD160;
    XCTAssertEqualObjects(@"0bdc9d2d256b3ee9daae347be6f4dc835a467ffe".hexToData, d, @"[NSData RMD160]");
}

@end
