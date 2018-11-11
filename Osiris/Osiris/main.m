//
//  main.m
//  Osiris
//
//  Created by Pwn20wnd on 10/28/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#include "ViewController.h"

int main(int argc, char * argv[]) {
    START_LOGGING();
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
