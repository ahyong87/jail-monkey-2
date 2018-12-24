//
//  JailMonkey.m
//  Trackops
//
//  Created by Gant Laborde on 7/19/16.
//  Copyright © 2016 Facebook. All rights reserved.
//

#import "JailMonkey.h"
#import <mach-o/dyld.h>
#import <sys/stat.h>

@import UIKit;

static NSString * const JMJailbreakTextFile = @"/private/jailbreak.txt";
static NSString * const JMisJailBronkenKey = @"isNotOriginal";
static NSString * const JMCanMockLocationKey = @"canMockLocation";

@implementation JailMonkey

RCT_EXPORT_MODULE();

+ (BOOL)requiresMainQueueSetup
{
    return YES;
}

- (NSArray *)pathsToCheck
{
    return @[
             @"/Applications/Cydia.app",
             @"/Library/MobileSubstrate/MobileSubstrate.dylib",
             @"/bin/bash",
             @"/usr/sbin/sshd",
             @"/etc/apt",
             @"/private/var/lib/apt",
             @"/private/var/stash",
             @"/private/var/tmp/cydia.log",
             @"/private/var/lib/cydia",
             @"/private/var/mobile/Library/SBSettings/Themes",
             @"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
             @"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
             @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
             @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
             @"/var/cache/apt",
             @"/var/lib/apt",
             @"/var/lib/cydia",
             @"/var/log/syslog",
             @"/var/tmp/cydia.log",
             @"/bin/sh",
             @"/usr/libexec/ssh-keysign",
             @"/usr/bin/sshd",
             @"/usr/libexec/sftp-server",
             @"/etc/ssh/sshd_config",
             @"/Applications/RockApp.app",
             @"/Applications/Icy.app",
             @"/Applications/WinterBoard.app",
             @"/Applications/SBSettings.app",
             @"/Applications/MxTube.app",
             @"/Applications/IntelliScreen.app",
             @"/Applications/FakeCarrier.app",
             @"/Applications/blackra1n.app",
             ];
}

- (NSArray *)schemesToCheck
{
    return @[
             @"cydia://package/com.example.package",
             @"cydia://package/com.masbog.com",
             ];
}

- (BOOL)checkPaths
{
    BOOL existsPath = NO;
    
    for (NSString *path in [self pathsToCheck]) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]){
            existsPath = YES;
            break;
        }
    }
    
    return existsPath;
}

- (BOOL)checkCydia{
    //check cydia if hook NSFileManager
    struct stat stat_info;
    if (0 == stat("/Applications/Cydia.app", &stat_info)) {
        return YES;
    }
    
    //check JailBreak generate Data Structure
    if (0 == stat("/private/var/lib/apt/", &stat_info)) {
        return YES;
    }
    
    if (0 == stat("/User/Applications/", &stat_info)) {
        return YES;
    }

    return NO;
}

- (BOOL)checkSchemes
{
    BOOL canOpenScheme = NO;
    
    for (NSString *scheme in [self schemesToCheck]) {
        if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:scheme]]){
            canOpenScheme = YES;
            break;
        }
    }
    
    return canOpenScheme;
}

- (BOOL)canViolateSandbox{
	NSError *error;
    BOOL grantsToWrite = NO;
	NSString *stringToBeWritten = @"This is an anti-spoofing test.";
	[stringToBeWritten writeToFile:JMJailbreakTextFile atomically:YES
						  encoding:NSUTF8StringEncoding error:&error];
	if(!error){
		//Device is jailbroken
		grantsToWrite = YES;
	}
    
    [[NSFileManager defaultManager] removeItemAtPath:JMJailbreakTextFile error:nil];
    
    return grantsToWrite;
}

- (BOOL)checkSymbolicLinks{
    struct stat s;
    if(lstat("/Applications", &s) 
        || lstat("/var/stash/Library/Ringtones", &s) 
        || lstat("/var/stash/Library/Wallpaper", &s)
        || lstat("/var/stash/usr/include", &s) 
        || lstat("/var/stash/usr/libexec", &s)  
        || lstat("/var/stash/usr/share", &s) 
        || lstat("/var/stash/usr/arm-apple-darwin9", &s))
    {
        if(s.st_mode & S_IFLNK){
            return YES;
        }
    }

    return NO;
}

- (BOOL)checkFork{
    // SandBox Integrity Check
    int pid = fork();
    if(!pid){
        return NO;
    }
    if(pid>=0)
    {
        return YES;
    }
}

- (BOOL)checkDyld{
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0 ; i < count; ++i) {
        char* substrate = "Library/MobileSubstrate/MobileSubstrate.dylib";
        
        if (strcmp(_dyld_get_image_name(i),substrate)==0) {
            return YES;
        }
    }
    return NO;
}

- (BOOL)checkEnv{
    //check Env
    char *env = getenv("DYLD_INSERT_LIBRARIES");
    if (env) {
        return YES;
    }
    return NO;
}

- (BOOL)checkStat{
    int ret;
    Dl_info dylib_info;
    int (*func_stat)(const char *,struct stat *) = stat;
    if ((ret = dladdr(func_stat, &dylib_info))) {
        NSLog(@"lib:%s",dylib_info.dli_fname);      //如果不是系统库，肯定被攻击了
        if (strcmp(dylib_info.dli_fname, "/usr/lib/system/libsystem_kernel.dylib")) {   //不相等，肯定被攻击了，相等为0
            return YES;
        }
    }
    return NO;
}

- (BOOL)isNotOriginal{
    return [self checkPaths] 
        || [self checkCydia] 
        || [self checkSchemes] 
        || [self canViolateSandbox] 
        || [self checkSymbolicLinks] 
        || [self checkFork] 
        || [self checkDyld]
        || [self checkEnv]
        || [self checkStat];
}

- (NSDictionary *)constantsToExport
{
	return @{
			 JMisJailBronkenKey: @(self.isNotOriginal),
			 JMCanMockLocationKey: @(self.isNotOriginal)
			};
}

@end
