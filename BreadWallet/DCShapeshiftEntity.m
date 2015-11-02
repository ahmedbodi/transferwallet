//
//  DCShapeshiftEntity.m
//  TransferWallet
//
//  Created by Quantum Explorer on 8/23/15.
//  Copyright (c) 2015 Aaron Voisine. All rights reserved.
//

#import "DCShapeshiftEntity.h"
#import "BRTransactionEntity.h"
#import "NSManagedObject+Sugar.h"
#import "DCShapeshiftManager.h"
#import "BRPeerManager.h"

@interface DCShapeshiftEntity()

@property(atomic,assign) BOOL checkingStatus;
@property (nonatomic, strong) NSTimer * checkStatusTimer;

@end

@implementation DCShapeshiftEntity

@dynamic inputAddress;
@dynamic inputCoinType;
@dynamic outputCoinType;
@dynamic shapeshiftStatus;
@dynamic withdrawalAddress;
@dynamic outputTransactionId;
@dynamic errorMessage;
@dynamic inputCoinAmount;
@dynamic outputCoinAmount;
@dynamic expiresAt;
@dynamic isFixedAmount;
@dynamic transaction;

@synthesize checkingStatus;
@synthesize checkStatusTimer;

-(NSString*)shapeshiftStatusString {
    switch ([self.shapeshiftStatus integerValue]) {
        case eShapeshiftAddressStatus_Complete:
            return @"Completed";
            break;
        case eShapeshiftAddressStatus_Failed:
            return self.errorMessage;
            break;
        case eShapeshiftAddressStatus_Unused:
            return @"Started Shapeshift";
            break;
        case eShapeshiftAddressStatus_NoDeposits:
            return @"Shapeshift Depositing";
            break;
        case eShapeshiftAddressStatus_Received:
            return @"Shapeshift in Progress";
            break;
        default:
            return @"Unknown";
    }
}

+(DCShapeshiftEntity*)shapeshiftHavingWithdrawalAddress:(NSString*)withdrawalAddress {
    DCShapeshiftEntity * previousShapeshift = [DCShapeshiftEntity anyObjectMatching:@"withdrawalAddress == %@ && shapeshiftStatus == %@",withdrawalAddress, @(eShapeshiftAddressStatus_Unused)];
    return previousShapeshift;
}

+(DCShapeshiftEntity*)registerShapeshiftWithInputAddress:(NSString*)inputAddress andWithdrawalAddress:(NSString*)withdrawalAddress withStatus:(eShapeshiftAddressStatus)shapeshiftAddressStatus{
    DCShapeshiftEntity * shapeshift = [DCShapeshiftEntity managedObject];
    shapeshift.inputAddress = inputAddress;
    shapeshift.withdrawalAddress = withdrawalAddress;
    shapeshift.shapeshiftStatus = @(shapeshiftAddressStatus);
    shapeshift.isFixedAmount = @NO;
    [self saveContext];
    return shapeshift;
}

+(DCShapeshiftEntity*)registerShapeshiftWithInputAddress:(NSString*)inputAddress andWithdrawalAddress:(NSString*)withdrawalAddress withStatus:(eShapeshiftAddressStatus)shapeshiftAddressStatus fixedAmountOut:(NSNumber*)amountOut amountIn:(NSNumber*)amountIn {
    DCShapeshiftEntity * shapeshift = [DCShapeshiftEntity managedObject];
    shapeshift.inputAddress = inputAddress;
    shapeshift.withdrawalAddress = withdrawalAddress;
    shapeshift.outputCoinAmount = amountOut;
    shapeshift.inputCoinAmount = amountIn;
    shapeshift.shapeshiftStatus = @(shapeshiftAddressStatus);
    shapeshift.isFixedAmount = @YES;
    shapeshift.expiresAt = [NSDate dateWithTimeIntervalSinceNow:540];  //9 minutes (leave 1 minute as buffer)
    [self saveContext];
    return shapeshift;
}

+(NSArray*)shapeshiftsInProgress {
    static uint32_t height = 0;
    uint32_t h = [[BRPeerManager sharedInstance] lastBlockHeight];
    if (h > 20) height = h - 20; //only care about shapeshifts in last 20 blocks
    NSArray * shapeshiftsInProgress = [DCShapeshiftEntity objectsMatching:@"(shapeshiftStatus == %@ || shapeshiftStatus == %@) && transaction.blockHeight > %@",@(eShapeshiftAddressStatus_NoDeposits), @(eShapeshiftAddressStatus_Received),@(height)];

    return shapeshiftsInProgress;
}

-(void)checkStatus {
    if (self.checkingStatus) {
        return;
    }
    self.checkingStatus = TRUE;
    [[DCShapeshiftManager sharedInstance] GET_transactionStatusWithAddress:self.inputAddress completionBlock:^(NSDictionary *transactionInfo, NSError *error) {
        self.checkingStatus = FALSE;
        if (transactionInfo) {
            NSString * status = transactionInfo[@"status"];
            if ([status isEqualToString:@"received"]) {
                if ([self.shapeshiftStatus integerValue] != eShapeshiftAddressStatus_Received)
                    self.shapeshiftStatus = @(eShapeshiftAddressStatus_Received);
                self.inputCoinAmount = transactionInfo[@"incomingCoin"];
                id inputCoinAmount = transactionInfo[@"incomingCoin"];
                if ([inputCoinAmount isKindOfClass:[NSNumber class]]) {
                    self.inputCoinAmount = inputCoinAmount;
                } else if ([inputCoinAmount isKindOfClass:[NSString class]]) {
                    self.inputCoinAmount = @([inputCoinAmount doubleValue]);
                }
                [DCShapeshiftEntity saveContext];
            } else if ([status isEqualToString:@"complete"]) {
                self.shapeshiftStatus = @(eShapeshiftAddressStatus_Complete);
                self.outputTransactionId = transactionInfo[@"transaction"];
                id inputCoinAmount = transactionInfo[@"incomingCoin"];
                if ([inputCoinAmount isKindOfClass:[NSNumber class]]) {
                    self.inputCoinAmount = inputCoinAmount;
                } else if ([inputCoinAmount isKindOfClass:[NSString class]]) {
                    self.inputCoinAmount = @([inputCoinAmount doubleValue]);
                }
                self.inputCoinAmount = transactionInfo[@"incomingCoin"];
                id outputCoinAmount = transactionInfo[@"outgoingCoin"];
                if ([outputCoinAmount isKindOfClass:[NSNumber class]]) {
                    self.outputCoinAmount = outputCoinAmount;
                } else if ([outputCoinAmount isKindOfClass:[NSString class]]) {
                    self.outputCoinAmount = @([outputCoinAmount doubleValue]);
                }
                [DCShapeshiftEntity saveContext];
                [self.checkStatusTimer invalidate];
            } else if ([status isEqualToString:@"failed"]) {
                self.shapeshiftStatus = @(eShapeshiftAddressStatus_Failed);
                self.errorMessage = transactionInfo[@"error"];
                [DCShapeshiftEntity saveContext];
                [self.checkStatusTimer invalidate];
            }
        }
    }];
}

-(void)routinelyCheckStatusAtInterval:(NSTimeInterval)timeInterval {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.checkStatusTimer) {
            [self.checkStatusTimer invalidate];
        }
        self.checkStatusTimer = [NSTimer scheduledTimerWithTimeInterval:timeInterval target:self selector:@selector(checkStatus) userInfo:nil repeats:YES];
    });
}

-(void)deleteObject {
    [self.checkStatusTimer invalidate];
    [super deleteObject];
}

@end
