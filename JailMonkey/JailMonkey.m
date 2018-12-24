//
//  JailMonkey.m
//  Trackops
//
//  Created by Gant Laborde on 7/19/16.
//  Copyright © 2016 Facebook. All rights reserved.
//

#import "JailMonkey.h"
#include <sys/stat.h>
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

- (BOOL)isNotOriginal{
    return [self checkPaths] || [self checkSchemes] || [self canViolateSandbox] || [self checkSymbolicLinks] || [self checkFork];
}

- (NSDictionary *)constantsToExport
{
	return @{
			 JMisJailBronkenKey: @(self.isNotOriginal),
			 JMCanMockLocationKey: @(self.isNotOriginal)
			 };
}

@end
