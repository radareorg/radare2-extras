// r2 plugin written by pancake @ 2021
/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2021 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#define D if (0)
#include <errno.h>
#include <fcntl.h>              // open
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>             // exit
#include <string.h>             // strlen, strerror, memcpy, memmove
#include <unistd.h>             // close
#include <wordexp.h>
#include <sys/mman.h>           // mmap, munmap
#include <sys/stat.h>           // fstst
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <r_io.h>
#include <r_lib.h>

#define LOG(fmt, ...) do { fprintf(stderr, "\x1b[1;96m" fmt "\x1b[0m\n", ##__VA_ARGS__); } while(0)
#define ERR(fmt, ...) do { fprintf(stderr, "\x1b[1;91m" fmt "\x1b[0m\n", ##__VA_ARGS__); } while(0)

// Keep in sync with Pongo
#define UPLOADSZ_MAX (1024 * 1024 * 128)

static char *__system(RIO *io, RIODesc *fd, const char *cmd);
typedef struct {
	volatile uint64_t regID;
	IOUSBDeviceInterface245 **dev;
	IOUSBInterfaceInterface245 **intf;
	pthread_t th;
} stuff_t;

static uint8_t gBlockIO = 1;
static int cmdfd[2];
static int resfd[2];

static IOReturn USBControlTransfer(IOUSBInterfaceInterface245 **intf, uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint32_t wLength, void *data, uint32_t *wLenDone)
{
	IOUSBDevRequest request =
	{
		.bmRequestType = bmRequestType,
		.bRequest = bRequest,
		.wValue = wValue,
		.wIndex = wIndex,
		.wLength = wLength,
		.pData = data,
	};
	IOReturn ret = (*intf)->ControlRequest(intf, 0, &request);
	if(wLenDone) *wLenDone = request.wLenDone;
	return ret;
}

static IOReturn USBBulkUpload(IOUSBInterfaceInterface245 **intf, void *data, uint32_t len)
{
	return (*intf)->WritePipe(intf, 2, data, len);
}

bool lefin = false;

static void write_stdout(char *obuf, uint32_t olen)
{
	static bool init = false;
	static char *buf = NULL;
	static ut32 len = 0;
	if (obuf) {
		if (olen == 0) {
			return;
		}
		char *rr = strchr (obuf, '\r');
		lefin = false;
		if (strstr (obuf, "pongoOS> \rpongoOS")) {
			lefin = true;
		}
		if (rr) {
			*rr = 0;
			olen = strlen (obuf);
			// eprintf ("R %d%c", rr- obuf, 10);
			lefin = (rr-obuf) == 0;
		}
#if 1
		char *prompt = strstr (obuf, "\rpongoOS>");
		if (prompt) {
			*prompt = 0;
			lefin = true;
			olen = strlen (obuf);
			// eprintf ("P%c", 10);
		}
#endif
		char *nbuf = realloc (buf, len + olen + 1);
		if (!nbuf) {
			return;
		}
		buf = nbuf;
		buf[len+olen] = 0;
		memcpy (buf + len, obuf, olen);
		len += olen;
		if (lefin || !*obuf || prompt) {
			//	write_stdout (NULL, 0);
			return;
		}
	} else {
		obuf = buf;
		if (!init) {
			init = true;
			return;
		}
		// end of buffer, flushing thru the fd!
		// 	write(1, buf, len);
		// write(resfd[1], buf, len);
		// eprintf ("flush %d %c", len, 10);
		write(resfd[1], &len, sizeof (len));
		// eprintf ("WRITE LEN %d (%s)%c", len, buf, 10);
		while(len > 0)
		{
			ssize_t s = write(resfd[1], buf, len);
			if(s < 0)
			{
				ERR("write: %s", strerror(errno));
				exit(-1);
			}
			buf += s;
			len -= s;
		}
		buf = obuf;
		R_FREE (buf);
		len = 0;
	}
}

static void* io_main(void *arg)
{
	stuff_t *stuff = arg;
	int r = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	if(r != 0)
	{
		ERR("pthread_setcancelstate: %s", strerror(r));
		exit(-1);
	}
	LOG("[Connected]");
	IOReturn ret = KERN_SUCCESS;
	char prompt[64] = "> ";
	uint32_t plen = 2;
	while(1)
	{
		char buf[0x2000] = {};
		uint32_t outpos = 0;
		uint32_t outlen = 0;
		uint8_t in_progress = 1;
		while(in_progress)
		{
			ret = USBControlTransfer(stuff->intf, 0xa1, 2, 0, 0, (uint32_t)sizeof(in_progress), &in_progress, NULL);
			if(ret == KERN_SUCCESS)
			{
				ret = USBControlTransfer(stuff->intf, 0xa1, 1, 0, 0, 0x1000, buf + outpos, &outlen);
				if(ret == KERN_SUCCESS)
				{
					if (outlen>0) {
						write_stdout(buf + outpos, outlen);
					}
					outpos += outlen;
					if(outpos > 0x1000)
					{
						memmove(buf, buf + outpos - 0x1000, 0x1000);
						outpos = 0x1000;
					}
				}
			}
			if(ret != KERN_SUCCESS)
			{
				goto bad;
			}
		}
		if(outpos > 0)
		{
			// Record prompt
			uint32_t start = outpos;
			for(uint32_t end = outpos > 64 ? outpos - 64 : 0; start > end; --start)
			{
				if(buf[start-1] == '\n')
				{
					break;
				}
			}
			plen = outpos - start;
			memcpy(prompt, buf + start, plen);
			// eprintf ("RECORD PROMPT%c", 10);
			if (plen>0 || !lefin) { // lefin)
				write_stdout(NULL, 0);
			}
		} else {
			// Re-emit prompt
			write_stdout(NULL, 0);
		}
		ret = USBControlTransfer(stuff->intf, 0x21, 4, 0xffff, 0, 0, NULL, NULL);
		if(ret != KERN_SUCCESS)
		{
			goto bad;
		}
		r = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		if(r != 0)
		{
			ERR("pthread_setcancelstate: %s", strerror(r));
			exit(-1);
		}
		// receive input from user in here
		size_t len = read(cmdfd[0], buf, sizeof (buf));
		if (len >= 0) {
			buf[len] = 10;
			buf[len + 1] = 0;
			len ++;
		}

#if 0
		while(1)
		{
			char ch;
			ssize_t s = read(0, &ch, 1);
			if(s == 0)
			{
				break;
			}
			if(s < 0)
			{
				if(errno == EINTR)
				{
					return NULL;
				}
				ERR("read: %s", strerror(errno));
				exit(-1);
			}
			if(len < sizeof(buf))
			{
				buf[len] = ch;
			}
			++len;
			if(ch == '\n')
			{
				break;
			}
		}
#endif
		r = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		if(r != 0)
		{
			ERR("pthread_setcancelstate: %s", strerror(r));
			exit(-1);
		}
		if(len == 0)
		{
			exit(0);
		}
		if(len > sizeof(buf))
		{
			ERR("Discarding command of >%zu chars", sizeof(buf));
			continue;
		}
		if(buf[0] == '/')
		{
			buf[len-1] = '\0';
			wordexp_t we;
			r = wordexp(buf + 1, &we, WRDE_SHOWERR | WRDE_UNDEF);
			if(r != 0)
			{
				ERR("wordexp: %d", r);
				continue;
			}
			bool show_help = false;
			if(we.we_wordc == 0)
			{
				show_help = true;
			}
			else if(strcmp(we.we_wordv[0], "send") == 0)
			{
				if(we.we_wordc == 1)
				{
					LOG("Usage: /send [file]");
					LOG("Upload a file to PongoOS. This should be followed by a command such as \"modload\".");
				}
				else
				{
					int fd = open(we.we_wordv[1], O_RDONLY);
					if(fd < 0)
					{
						ERR("Failed to open file: %s", strerror(errno));
					}
					else
					{
						struct stat s;
						r = fstat(fd, &s);
						if(r != 0)
						{
							ERR("Failed to stat file: %s", strerror(errno));
						}
						else
						{
							void *addr = mmap(NULL, s.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
							if(addr == MAP_FAILED)
							{
								ERR("Failed to map file: %s", strerror(errno));
							}
							else
							{
								uint32_t newsz = s.st_size;
								ret = USBControlTransfer(stuff->intf, 0x21, 1, 0, 0, 4, &newsz, NULL);
								if(ret == KERN_SUCCESS)
								{
									ret = USBBulkUpload(stuff->intf, addr, s.st_size);
									if(ret == KERN_SUCCESS)
									{
										LOG("Uploaded %llu bytes", s.st_size);
									}
								}
								munmap(addr, s.st_size);
							}
						}
						close(fd);
					}
				}
			}
			else
			{
				ERR("Unrecognised command: /%s", we.we_wordv[0]);
				show_help = true;
			}
			if(show_help)
			{
				LOG("Available commands:");
				LOG("/send [file] - Upload a file to PongoOS");
			}
			wordfree(&we);
		}
		else
		{
			if(len > sizeof(buf))
			{
				ERR("PongoOS currently only supports commands with 512 characters or less");
				continue;
			}
			if(gBlockIO)
			{
				ret = USBControlTransfer(stuff->intf, 0x21, 4, 1, 0, 0, NULL, NULL);
			}
			if(ret == KERN_SUCCESS)
			{
				ret = USBControlTransfer(stuff->intf, 0x21, 3, 0, 0, (uint32_t)len, buf, NULL);
			}
		}
		if(ret != KERN_SUCCESS)
		{
			goto bad;
		}
	}
bad:;
    if(ret == kIOReturnNotResponding)
    {
	    return NULL;
    }
    ERR("USBControlTransfer: %s", mach_error_string(ret));
    exit(-1);
}

static void FoundDevice(void *refCon, io_iterator_t it)
{
	stuff_t *stuff = refCon;
	if(stuff->regID)
	{
		return;
	}
	io_service_t usbDev = MACH_PORT_NULL;
	while((usbDev = IOIteratorNext(it)))
	{
		uint64_t regID;
		kern_return_t ret = IORegistryEntryGetRegistryEntryID(usbDev, &regID);
		if(ret != KERN_SUCCESS)
		{
			ERR("IORegistryEntryGetRegistryEntryID: %s", mach_error_string(ret));
			goto next;
		}
		SInt32 score = 0;
		IOCFPlugInInterface **plugin = NULL;
		ret = IOCreatePlugInInterfaceForService(usbDev, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
		if(ret != KERN_SUCCESS)
		{
			ERR("IOCreatePlugInInterfaceForService(usbDev): %s", mach_error_string(ret));
			goto next;
		}
		HRESULT result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (LPVOID*)&stuff->dev);
		(*plugin)->Release(plugin);
		if(result != 0)
		{
			ERR("QueryInterface(dev): 0x%x", result);
			goto next;
		}
		ret = (*stuff->dev)->USBDeviceOpenSeize(stuff->dev);
		if(ret != KERN_SUCCESS)
		{
			ERR("USBDeviceOpenSeize: %s", mach_error_string(ret));
		}
		else
		{
			ret = (*stuff->dev)->SetConfiguration(stuff->dev, 1);
			if(ret != KERN_SUCCESS)
			{
				ERR("SetConfiguration: %s", mach_error_string(ret));
			}
			else
			{
				IOUSBFindInterfaceRequest request =
				{
					.bInterfaceClass = kIOUSBFindInterfaceDontCare,
					.bInterfaceSubClass = kIOUSBFindInterfaceDontCare,
					.bInterfaceProtocol = kIOUSBFindInterfaceDontCare,
					.bAlternateSetting = kIOUSBFindInterfaceDontCare,
				};
				io_iterator_t iter = MACH_PORT_NULL;
				ret = (*stuff->dev)->CreateInterfaceIterator(stuff->dev, &request, &iter);
				if(ret != KERN_SUCCESS)
				{
					ERR("CreateInterfaceIterator: %s", mach_error_string(ret));
				}
				else
				{
					io_service_t usbIntf = MACH_PORT_NULL;
					while((usbIntf = IOIteratorNext(iter)))
					{
						ret = IOCreatePlugInInterfaceForService(usbIntf, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
						IOObjectRelease(usbIntf);
						if(ret != KERN_SUCCESS)
						{
							ERR("IOCreatePlugInInterfaceForService(usbIntf): %s", mach_error_string(ret));
							continue;
						}
						result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID), (LPVOID*)&stuff->intf);
						(*plugin)->Release(plugin);
						if(result != 0)
						{
							ERR("QueryInterface(intf): 0x%x", result);
							continue;
						}
						ret = (*stuff->intf)->USBInterfaceOpen(stuff->intf);
						if(ret != KERN_SUCCESS)
						{
							ERR("USBInterfaceOpen: %s", mach_error_string(ret));
						}
						else
						{
							int r = pthread_create(&stuff->th, NULL, &io_main, stuff);
							if(r != 0)
							{
								ERR("pthread_create: %s", strerror(r));
								exit(-1);
							}
							stuff->regID = regID;
							while((usbIntf = IOIteratorNext(iter))) IOObjectRelease(usbIntf);
							IOObjectRelease(iter);
							while((usbDev = IOIteratorNext(it))) IOObjectRelease(usbDev);
							IOObjectRelease(usbDev);
							return;
						}
						(*stuff->intf)->Release(stuff->intf);
						stuff->intf = NULL;
					}
					IOObjectRelease(iter);
				}
			}
		}

next:;
		if (stuff->dev) {
			(*stuff->dev)->Release(stuff->dev);
			stuff->dev = NULL;
		}
		IOObjectRelease(usbDev);
	}
}

static void LostDevice(void *refCon, io_iterator_t it)
{
	stuff_t *stuff = refCon;
	io_service_t usbDev = MACH_PORT_NULL;
	while((usbDev = IOIteratorNext(it)))
	{
		uint64_t regID;
		kern_return_t ret = IORegistryEntryGetRegistryEntryID(usbDev, &regID);
		IOObjectRelease(usbDev);
		if(ret == KERN_SUCCESS && stuff->regID == regID)
		{
			LOG("[Disconnected]");
			int r = pthread_cancel(stuff->th);
			if(r != 0)
			{
				ERR("pthread_cancel: %s", strerror(r));
				exit(-1);
			}
			r = pthread_join(stuff->th, NULL);
			if(r != 0)
			{
				ERR("pthread_join: %s", strerror(r));
				exit(-1);
			}
			stuff->regID = 0;
			(*stuff->intf)->USBInterfaceClose(stuff->intf);
			(*stuff->intf)->Release(stuff->intf);
			(*stuff->dev)->Release(stuff->dev);
		}
	}
}

#if 0
	int moan(int argc, const char **argv)
if(argc > 2)
{
	ERR("Usage: %s [-n]", argv[0]);
	return -1;
}
if(argc == 2)
{
	if(strcmp(argv[1], "-n") == 0)
	{
		gBlockIO = 0;
	}
	else
	{
		ERR("Bad arg: %s", argv[1]);
		return -1;
	}
}
#endif

pthread_t main_th;
static void *main_loop(void *foo) {
	kern_return_t ret;
	stuff_t stuff = {};
	io_iterator_t found, lost;
	NSDictionary *dict =
		@{
			@"IOProviderClass": @"IOUSBDevice",
			@"idVendor":  @0x05ac,
			@"idProduct": @0x4141,
		};
	CFDictionaryRef cfdict = (__bridge CFDictionaryRef)dict;
	IONotificationPortRef notifyPort = IONotificationPortCreate(kIOMasterPortDefault);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(notifyPort), kCFRunLoopDefaultMode);

	CFRetain(cfdict);
	ret = IOServiceAddMatchingNotification(notifyPort, kIOFirstMatchNotification, cfdict, &FoundDevice, &stuff, &found);
	if(ret != KERN_SUCCESS)
	{
		ERR("IOServiceAddMatchingNotification: %s", mach_error_string(ret));
		return NULL;
	}
	FoundDevice(&stuff, found);

	CFRetain(cfdict);
	ret = IOServiceAddMatchingNotification(notifyPort, kIOTerminatedNotification, cfdict, &LostDevice, &stuff, &lost);
	if(ret != KERN_SUCCESS)
	{
		ERR("IOServiceAddMatchingNotification: %s", mach_error_string(ret));
		return NULL;
	}
	LostDevice(&stuff, lost);
	CFRunLoopRun(); // this is blocking wtf
	return NULL;
}

static int open_pongo_term(void) {
	pipe(cmdfd);
	pipe(resfd);
	int r = pthread_create(&main_th, NULL, &main_loop, NULL);
	if(r != 0)
	{
		ERR("pthread_create: %s", strerror(r));
		exit(-1);
	}
	return -1;
}


static ut8 read_hex_byte(const char *s) {
	ut8 b = 0;
	ut8 r = 0;
	r_hex_to_byte (&b, s[0]);
	r = b;
	r_hex_to_byte (&b, s[1]);
	r |= (b << 4);
	return b;
}

int hexletobuf(ut8 *out, const char *s, int left) {
	if (left > 0) out[3] = read_hex_byte (s);
	if (left > 1) out[2] = read_hex_byte (s + 2);
	if (left > 2) out[1] = read_hex_byte (s + 4);
	if (left > 3) out[0] = read_hex_byte (s + 6);
	return R_MIN (4, left);
}

// r2 stuff 
static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
	ut64 addr = io->off;
	if (addr < 0x10000000) {
		return -1;
	}
	// eprintf ("READ %llx %d%c", io->off, len, 10);
#if 0
	if (addr < 0x100000000 || addr > 0x200000000) {
		return len;
	}
#endif
	ut8 *out = buf;
	int left = len;
	int delta = 0;
	while (left > 0) {
		char *cmd = r_str_newf ("peek 0x%"PFMT64x, io->off + delta);
		D eprintf ("< (%s)%c", cmd, 10);
		char *res = __system (io, desc, cmd);
		D eprintf ("> (%s)%c", res, 10);
		if (res) {
			// 0x100000000: aa0803e9 (e9 3 8 aa)
			char *s = strchr (res, ' ');
			if (s) {
				s++;
				char *e = strchr (s, ' ');
				if (e) {
					*e = 0;
				}
				hexletobuf (out, s, left);
			}
			free (res);
		}
		free (cmd);
		if (!res) {
			eprintf ("read error\n");
			return -1;
			break;
		}
		out += 4;
		left -= 4;
		delta += 4;
	}
	return len;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	ut64 addr = io->off;
	if (addr < 0x10000000) {
		return -1;
	}
	// eprintf ("READ %llx %d%c", io->off, len, 10);
#if 0
	if (addr < 0x100000000 || addr > 0x200000000) {
		return len;
	}
#endif
	int left = len;
	int delta = 0;
	while (left > 0) {
		ut32 v32 = 0;
		memcpy (&v32, buf + delta, sizeof (v32));
		char *cmd = r_str_newf ("poke 0x%"PFMT64x" 0x%08x", io->off + delta, v32);
		D eprintf ("< (%s)%c", cmd, 10);
		char *res = __system (io, fd, cmd);
		D eprintf ("> (%s)%c", res, 10);
		free (res);
		free (cmd);
		if (!res) {
			eprintf ("read error\n");
			return -1;
			break;
		}
		left -= 4;
		delta += 4;
	}
	return len;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET:
		io->off = offset;
		break;
	case R_IO_SEEK_CUR:
		io->off += offset;
		break;
	case R_IO_SEEK_END:
		io->off = ST64_MAX;
		break;
	}
	return io->off;
}

extern RIOPlugin r_io_plugin_pongo;

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return (!strncmp (file, "pongo://", 9));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (!__plugin_open (io, file, false)) {
		return NULL;
	}
	RIODesc *ret = r_io_desc_new (io, &r_io_plugin_pongo, file,
			rw | R_PERM_X, mode, NULL);
	open_pongo_term ();
	return ret;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (strlen (cmd) == 0) {
		return NULL;
	}
	char *nl = r_str_newf ("%s\n", cmd);
	write (cmdfd[1], nl, strlen (nl));// cmd, strlen (cmd));
	free (nl);
	ut32 reslen = 0;
	int r = read (resfd[0], &reslen, sizeof (reslen));
	if (r != sizeof (reslen)) {
		eprintf ("Cannot read resfd %c", 10);
		return NULL;
	}
	int len = reslen;
	if (len < 1) {
		return strdup("");
	}
	char *res = calloc (1, reslen + 1);
	if (!res) {
		return NULL;
	}
	char *buf = res;
	while (len > 0) {
		ssize_t s = read (resfd[0], buf, R_MIN (len, 128));
		if (s < 0) {
			ERR("write: %s", strerror(errno));
			free (res);
			return NULL;
		}
		buf += s;
		len -= s;
	}
	return res;
}

static int __close(RIODesc *fd) {
	if (!fd) {
		return -1;
	}
	// = fd->data;
	return 0;
}

RIOPlugin r_io_plugin_pongo = {
	.name = "pongo",
	.desc = "Attach to iDevice running pongoOS",
	.author = "pancake <pancake@nopcode.org>",
	.license = "MIT",
	.uris = "pongo://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write
};

R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_pongo,
	.version = R2_VERSION
};
