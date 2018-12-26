/*
Copyright (C) 2018-2019 by Student Main (https://github.com/studentmain)

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32))
#define __WINDOWS__
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "thirdparty/cJSON.h"		// https://github.com/DaveGamble/cJSON
#include "thirdparty/qrcodegen.h"	// https://www.nayuki.io/page/qr-code-generator-library#c

#ifdef __WINDOWS__
#include <windows.h>
HANDLE h;
WORD OldAttr;
WORD FGWHITE = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
WORD BGWHITE = BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY;
void prepare()
{
    CONSOLE_SCREEN_BUFFER_INFO info;
    h = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(h, &info);
    OldAttr = info.wAttributes;
}
void white()
{
    SetConsoleTextAttribute(h, FGWHITE | BGWHITE);
    fputs("##", stdout);
}

void black()
{
    SetConsoleTextAttribute(h, 0);
    fputs("  ", stdout);
}
void clear()
{
    SetConsoleTextAttribute(h, OldAttr);
}
#else
void
prepare()
{
}
void white()
{
    fputs("\e[37;47m##", stdout);
}

void black()
{
    fputs("\e[30;40m  ", stdout);
}
void clear()
{
    fputs("\e[0m", stdout);
}
#endif

void check(void* ptr, char* msg)
{
	if(ptr) return;
	perror(msg);
	exit(-1);
}
void help(void)
{
	printf("ss-share [configpath] [servername]");
	exit(0);
}
const char conv[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345689+/";
char *base64_encode(char *in)
{
    size_t inlen = strlen(in);
    size_t tuplecount = (inlen + 2) / 3;
    size_t outlen = tuplecount * 4;
    char *out = malloc(outlen * sizeof(char));
    size_t inpos = 0;
    size_t outpos = 0;
    char inbuf[3];
    char outbuf[4];
    while (inlen - inpos >= 3)
    {
        memcpy(inbuf, in + inpos, 3);
        outbuf[0] = (inbuf[0] & 0b11111100) >> 2;
        outbuf[1] = (inbuf[0] & 0b00000011) << 4 | (inbuf[1] & 0b11110000) >> 4;
        outbuf[2] = (inbuf[1] & 0b00001111) << 2 | (inbuf[2] & 0b11000000) >> 6;
        outbuf[3] = (inbuf[2] & 0b00111111);
        out[outpos + 0] = conv[outbuf[0]];
        out[outpos + 1] = conv[outbuf[1]];
        out[outpos + 2] = conv[outbuf[2]];
        out[outpos + 3] = conv[outbuf[3]];
        inpos += 3;
        outpos += 4;
    }
    switch (inlen - inpos)
    {
    case 0:
        break;
    case 1:
        outbuf[0] = (in[inpos] & 0b11111100) >> 2;
        outbuf[1] = (in[inpos] & 0b00000011) << 4;
        out[outpos + 0] = conv[outbuf[0]];
        out[outpos + 1] = conv[outbuf[1]];
        out[outpos + 2] = 0;
        out[outpos + 3] = 0;
        outpos += 2;
        break;
    case 2:
        outbuf[0] = (in[inpos] & 0b11111100) >> 2;
        outbuf[1] = (in[inpos] & 0b00000011) << 4 | (in[inpos + 1] & 0b11110000) >> 4;
        outbuf[2] = (in[inpos + 1] & 0b00001111) << 2;
        out[outpos + 0] = conv[outbuf[0]];
        out[outpos + 1] = conv[outbuf[1]];
        out[outpos + 2] = conv[outbuf[2]];
        out[outpos + 3] = 0;
        outpos += 3;
        break;
    }
    out[outpos] = 0;
    return out;
}

void printqr(char *in)
{
    enum qrcodegen_Ecc errCorLvl = qrcodegen_Ecc_LOW;
    char qrcode[qrcodegen_BUFFER_LEN_MAX];
    char tempBuffer[qrcodegen_BUFFER_LEN_MAX];
    bool ok = qrcodegen_encodeText(in, tempBuffer, qrcode, errCorLvl, qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true);
    if (ok)
    {
        prepare();
        int size = qrcodegen_getSize(qrcode);
        int border = 1;
        for (int y = -border; y < size + border; y++)
        {
            for (int x = -border; x < size + border; x++)
            {
                qrcodegen_getModule(qrcode, x, y) ? black() : white();
            }
            clear();
            fputs("\n", stdout);
        }
        clear();
        fputs("\n", stdout);
    }
}

const char* data[] = {
    "example.json",
	"/etc/shadowsocks-libev/config.json"
};

int main(int argc, char **argv)
{
    // assume configure file is less than 64k
    char *buf[4096];
    char *bufptr = buf;
    int remainsz = 4096;
    FILE *f = NULL;
	for (int i = 0; i < sizeof(data)/sizeof(data[0]); i++)
	{
		f = fopen(data[i], "r");
		if(f) break;
	}
	check(f, "fopen");
    int l;
    while (1)
    {
        fgets(bufptr, remainsz, f);
        l = strlen(bufptr);
        remainsz -= l;
        bufptr += l;
        if (l == 0)
            break;
    }
    bufptr[0] = 0;
    cJSON *json = cJSON_Parse(buf);
	check(json,"cJSON_Parse");
    char *server = NULL;
    if (argc > 2)
    {
        if (argv[2][0] != '-' || argv[2][1] != 0)
        {
            server = argv[2];
        }
    }
    if (!server)
        server = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "server"));
    if (!server||strcmp(server,"0.0.0.0") == 0)
        server = "";
    char *passwd = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "password"));
    char *method = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "method"));
    int port = cJSON_GetObjectItemCaseSensitive(json, "server_port")->valueint;

    char *b64 = malloc((strlen(method) + strlen(passwd) + 5) * sizeof(char));
    sprintf(b64, "%s:%s", method, passwd);
    char *b64out = base64_encode(b64);
    char *out = malloc((strlen(b64out) * 2) * sizeof(char));
    sprintf(out, "ss://%s@%s:%d\n", b64out, server, port);
    puts(out);
    printqr(out);
}
