//
//  NSString+DCAdditions.m
//  TransferWallet
//
//  Created by Quantum Explorer on 4/25/15.
//  Copyright (c) 2015 Aaron Voisine. All rights reserved.
//

#import "NSString+DCAdditions.h"

@implementation NSString(DCAdditions)

//create a nice string to show the denominations
+(NSString*)stringFromDenomation:(NSInteger)denomination {
    // Function returns as follows:
    //
    // bit 0 - 100DRK+1 ( bit on if present )
    // bit 1 - 10DRK+1
    // bit 2 - 1DRK+1
    // bit 3 - .1DRK+1
    // bit 3 - non-denom
    
    
    NSMutableString * denominationString = [@"" mutableCopy];
    
    if(denomination & (1 << 0)) {
        if(denominationString.length > 0) [denominationString appendString:@"+"];
        [denominationString appendString:@"100"];
    }
    
    if(denomination & (1 << 1)) {
        if(denominationString.length > 0) [denominationString appendString:@"+"];
        [denominationString appendString:@"10"];;
    }
    
    if(denomination & (1 << 2)) {
        if(denominationString.length > 0) [denominationString appendString:@"+"];
        [denominationString appendString:@"1"];;
    }
    
    if(denomination & (1 << 3)) {
        if(denominationString.length > 0) [denominationString appendString:@"+"];
        [denominationString appendString:@"0.1"];;
    }
    return [NSString stringWithString:denominationString];
}

@end
