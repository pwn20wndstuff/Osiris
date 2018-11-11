//
//  ViewController.h
//  Osiris
//
//  Created by Pwn20wnd on 10/28/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>

#define K_BOOT_NONCE         "BootNonce"

#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define _assert(test) do \
    if (!(test)) { \
        fprintf(stderr, "__assert(%d:%s)@%s:%u[%s]\n", errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
    } \
while (false)

#define LOG_FILE             [[NSString stringWithFormat:@"%@/Documents/log_file.txt", NSHomeDirectory()] UTF8String]

#define ISDEBUGGERATTACHED() (getppid() == 1)

#define START_LOGGING() do { \
    if (ISDEBUGGERATTACHED()) { \
        freopen(LOG_FILE, "a+", stderr); \
        freopen(LOG_FILE, "a+", stdout); \
        setbuf(stdout, NULL); \
        setbuf(stderr, NULL);\
    } \
} while (false) \

#define RESET_LOGS() do { \
    if (ISDEBUGGERATTACHED()) { \
        if (!access(LOG_FILE, F_OK)) { \
            unlink(LOG_FILE); \
        } \
    } \
} while(false) \

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

