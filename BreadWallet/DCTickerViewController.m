//
//  DCTickerViewController.m
//  TransferWallet
//
//  Created by Quantum Explorer on 7/19/15.
//  Copyright (c) 2015 Aaron Voisine. All rights reserved.
//

#import "DCTickerViewController.h"
#import "Area.h"
#import "BarSeries.h"
#import "StockSeries.h"
#import "BBChartView.h"
#import "BBTheme.h"

@interface DCTickerViewController()

@property (nonatomic,strong) IBOutlet BBChartView * chartView;

@end

@implementation DCTickerViewController

-(void)refreshChartView {
    //ChartView add area, area add series
    Area* areaup = [[Area alloc] init];
    Area* areadown = [[Area alloc] init];
    BarSeries* bar = [[BarSeries alloc] init];
    StockSeries* stock = [[StockSeries alloc] init];
    [areaup addSeries:stock];
    [areadown addSeries:bar];
    
    // add data to bar and stock
    // [stock addPoint:]
    [self.chartView addArea:areaup];
    [self.chartView addArea:areadown];
    // two area's height ratio
    [self.chartView setHeighRatio:0.3 forArea:areadown];
    
    // set any color you like
    [BBTheme theme].barBorderColor = [UIColor clearColor];
    [BBTheme theme].xAxisFontSize = 11;
    
    // begin to show the view animated
    [self.chartView drawAnimated:YES];
}

@end
