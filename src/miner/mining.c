/*
 * mining.c - Mining engine utilities for FlowCoin solo miner.
 */

#include "mining.h"
#include <stdio.h>

void format_hashrate(double hr, char *buf, int bufsize)
{
    if (hr >= 1e12)
        snprintf(buf, bufsize, "%.2f TH/s", hr / 1e12);
    else if (hr >= 1e9)
        snprintf(buf, bufsize, "%.2f GH/s", hr / 1e9);
    else if (hr >= 1e6)
        snprintf(buf, bufsize, "%.2f MH/s", hr / 1e6);
    else if (hr >= 1e3)
        snprintf(buf, bufsize, "%.2f KH/s", hr / 1e3);
    else
        snprintf(buf, bufsize, "%.0f H/s", hr);
}
