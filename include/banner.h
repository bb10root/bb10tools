#ifndef _BANNER_H_INCLUDED
#define _BANNER_H_INCLUDED
#define APP_AUTHOR "Oleksandr <oleksandr@e.email>"
#define BUILD_INFO __DATE__ " " __TIME__

void display_system_banner()
{
    printf("----------------------------------------------------\n");
    printf("  %s\n", APP_NAME);
    printf("  Version:  %s\n", APP_VERSION);
    printf("  Author:   %s\n", APP_AUTHOR);
    printf("  Build:    %s\n", BUILD_INFO);
    printf("----------------------------------------------------\n");
}
#endif