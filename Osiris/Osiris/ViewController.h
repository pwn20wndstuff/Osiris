//
//  ViewController.h
//  Osiris
//
//  Created by Pwn20wnd on 10/28/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>

#define K_BOOT_NONCE "BootNonce"

@interface ViewController : UIViewController

enum {
    EMPTY_LIST = 0,
    MULTI_PATH = 1,
    ASYNC_WAKE = 2,
};
@property (weak, nonatomic) IBOutlet UILabel *KernelExploitLabel;
@property (weak, nonatomic) IBOutlet UIButton *DoItButton;
@property (weak, nonatomic) IBOutlet UIButton *BootNonceButton;

@end

