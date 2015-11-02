//
//  DCShapeshiftEntity.h
//  TransferWallet
//
//  Created by Quantum Explorer on 8/23/15.
//  Copyright (c) 2015 Aaron Voisine. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreData/CoreData.h>

typedef enum eShapeshiftAddressStatus {
    eShapeshiftAddressStatus_Unused = 0,
    eShapeshiftAddressStatus_NoDeposits = 1,
    eShapeshiftAddressStatus_Received = 2,
    eShapeshiftAddressStatus_Complete = 4,
    eShapeshiftAddressStatus_Failed = 8,
    eShapeshiftAddressStatus_Finished = eShapeshiftAddressStatus_Complete | eShapeshiftAddressStatus_Failed,
} eShapeshiftAddressStatus;


@class BRTransactionEntity;

@interface DCShapeshiftEntity : NSManagedObject

@property (nonatomic, retain) NSString * inputAddress;
@property (nonatomic, retain) NSString * inputCoinType;
@property (nonatomic, retain) NSString * outputCoinType;
@property (nonatomic, retain) NSNumber * shapeshiftStatus;
@property (nonatomic, retain) NSString * withdrawalAddress;
@property (nonatomic, retain) NSString * outputTransactionId;
@property (nonatomic, retain) NSString * errorMessage;
@property (nonatomic, retain) NSNumber * inputCoinAmount;
@property (nonatomic, retain) NSNumber * outputCoinAmount;
@property (nonatomic, retain) NSDate * expiresAt;
@property (nonatomic, retain) NSNumber * isFixedAmount;
@property (nonatomic, retain) BRTransactionEntity *transaction;

-(NSString*)shapeshiftStatusString;

-(void)checkStatus;

+(NSArray*)shapeshiftsInProgress;

+(DCShapeshiftEntity*)shapeshiftHavingWithdrawalAddress:(NSString*)withdrawalAddress;
+(DCShapeshiftEntity*)registerShapeshiftWithInputAddress:(NSString*)inputAddress andWithdrawalAddress:(NSString*)withdrawalAddress withStatus:(eShapeshiftAddressStatus)shapeshiftAddressStatus;
+(DCShapeshiftEntity*)registerShapeshiftWithInputAddress:(NSString*)inputAddress andWithdrawalAddress:(NSString*)withdrawalAddress withStatus:(eShapeshiftAddressStatus)shapeshiftAddressStatus fixedAmountOut:(NSNumber*)amountOut amountIn:(NSNumber*)amountIn;

-(void)routinelyCheckStatusAtInterval:(NSTimeInterval)timeInterval;

@end
