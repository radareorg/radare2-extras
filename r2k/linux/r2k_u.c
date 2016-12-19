
/*
	Just tiny program to test the module. Sanity checks not done
*/

#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#define CHAR_FMT "%c "
#define HEX_FMT "0x%02x "

#define HEX 	0x0
#define CHAR 	0x1

struct r2k_data {
	int pid;
        unsigned long addr;
        unsigned long len;
        unsigned char *buff;
};

#define MAX_PHYS_ADDR   128

struct kernel_map_info {
        unsigned long start_addr;
        unsigned long end_addr;
        unsigned long phys_addr[MAX_PHYS_ADDR];
        int n_pages;
        int n_phys_addr;
};

struct kernel_maps {
        int n_entries;
        int size;
};

#define R2_TYPE 0x69

#define IOCTL_READ_KERNEL_MEMORY	_IOR (R2_TYPE, 0x1, sizeof (struct r2k_data))
#define IOCTL_WRITE_KERNEL_MEMORY	_IOR (R2_TYPE, 0x2, sizeof (struct r2k_data))
#define IOCTL_READ_PROCESS_ADDR         _IOR (R2_TYPE, 0x3, sizeof (struct r2k_data))
#define IOCTL_WRITE_PROCESS_ADDR	_IOR (R2_TYPE, 0x4, sizeof (struct r2k_data))
#define IOCTL_READ_PHYSICAL_ADDR	_IOR (R2_TYPE, 0x5, sizeof (struct r2k_data))
#define IOCTL_WRITE_PHYSICAL_ADDR       _IOR (R2_TYPE, 0x6, sizeof (struct r2k_data))
#define IOCTL_GET_KERNEL_MAP            _IOR (R2_TYPE, 0x7, sizeof (struct r2k_data))

#define READ_KERNEL_MEMORY		0x1
#define WRITE_KERNEL_MEMORY		0x2
#define READ_PROCESS_ADDR		0x3
#define WRITE_PROCESS_ADDR		0x4
#define READ_PHYSICAL_ADDR		0x5
#define WRITE_PHYSICAL_ADDR		0x6
#define GET_KERNEL_MAP			0x7

const char *ioctl_str[] = 	{
					"IOCTL_READ_KERNEL_MEMORY",
					"IOCTL_WRITE_KERNEL_MEMORY",
					"IOCTL_READ_PROCESS_ADDR",
					"IOCTL_WRITE_PROCESS_ADDR",
					"IOCTL_READ_PHYSICAL_ADDR",
					"IOCTL_WRITE_PHYSICAL_ADDR",
					"IOCTL_GET_PROC_MAPS",
					"IOCTL_GET_KERNEL_MAP"
				};

const char *devicename = "/dev/r2k";
const char *prog_name;

void print_help(void)
{
	printf ("%s -a [addr] -i [ioctl] -b [n_bytes] -w [w_bytes] -p [pid]\n", prog_name);
	exit (-1);
}


int main(int argc, char **argv)
{

	int fd;
	int ret;
	int i;
	int j;
	int opt;
	int n_bytes;
	int n_ioctl;
	unsigned int ioctl_n;
	struct r2k_data data;
	struct kernel_maps map_data;
	struct kernel_map_info *info;
	unsigned char c = 98;
	char *p;
	char *str;
	int output;

	data.addr = data.pid = data.len = 0;
	prog_name = argv[0];
	output = HEX;
	ioctl_n = 0;

/*	if (argc < 4)
		print_help(); */

	while ((opt = getopt (argc, argv, "a:i:b:w:p:o:")) != -1) {
		switch (opt) {
		case 'a':
			data.addr = strtoul (optarg, &p, 16);
			break;
		case 'i':
			n_ioctl = atoi (optarg);
			if (n_ioctl < 1 || n_ioctl > 8) {
				printf ("ioctl from 1 to 8\n");
				exit (-1);
			}
			break;
		case 'b':
			n_bytes = atoi (optarg);
			break;
		case 'w':
			printf ("str = optarg\n");
			str = optarg;
			printf ("str = optarg\n");
			n_bytes = strlen (str);
			printf ("str = optarg\n");
		case 'p':
			data.pid = atoi (optarg);
			break;
		case 'o':
			output = *optarg == 'h'  ? HEX : CHAR;
			break;
		default:
			printf ("%s: arg %s not valid\n", prog_name, optarg);
			break;
		}
	}

	if (!n_ioctl)
		print_help();

	printf ("ioctl: %s\n", ioctl_str[n_ioctl - 1]);
	printf ("ioctl: addr 0x%lx\n", data.addr);
	printf ("ioctl: %d bytes\n", n_bytes);
	
	if (data.pid)
		printf ("ioctl: pid (%d)\n", data.pid);

	fd = open (devicename, O_RDONLY);
        if( fd == -1 ) {
                perror ("open error");
                return -1;
        }

	

	switch (n_ioctl) {
	case READ_KERNEL_MEMORY:

		data.buff = (unsigned char *)calloc (n_bytes, 1);
		data.len = n_bytes;

		ioctl_n = IOCTL_READ_KERNEL_MEMORY;
		ret = ioctl (fd, ioctl_n, &data);

		printf ("ret: %d\n", ret);
		fprintf (stderr, "ioctl err: %s\n", strerror (errno));

		if (!ret) {
			printf ("Got the state: addr: 0x%lx - value: ", data.addr);
			for (i = 0; i < n_bytes; i++) {
				printf (output == HEX ? HEX_FMT : CHAR_FMT , data.buff[i]);
			}
		}

		break;

	case WRITE_KERNEL_MEMORY:

		data.buff = (unsigned char *)calloc (n_bytes, 1);
		data.len = n_bytes;
		strncpy (data.buff, str, data.len);

		printf ("data.buff: %x\n", *data.buff);	
		
		ioctl_n = IOCTL_WRITE_KERNEL_MEMORY;
		ret = ioctl (fd, ioctl_n, &data); 
		fprintf (stderr, "ioctl err: %s\n", strerror (errno));
		break;

	case READ_PROCESS_ADDR:

		data.buff = (unsigned char *)calloc (n_bytes, 1);
		data.len = n_bytes;

		printf ("Reading %d bytes at 0x%lx from pid (%d)\n", data.len, data.addr, data.pid);

		ioctl_n = IOCTL_READ_PROCESS_ADDR;
		ret = ioctl (fd, ioctl_n, &data);
		printf ("ret: %d\n", ret);
		fprintf (stderr, "ioctl err: %s\n", strerror (errno));

		if (!ret) {
			printf ("Got the state: addr: 0x%lx - value: ", data.addr);
			for (i = 0; i < n_bytes; i++) {
				printf (output == HEX ? HEX_FMT : CHAR_FMT, data.buff[i]);
			}
		}

		break;

	case WRITE_PROCESS_ADDR:

		data.buff = (unsigned char *)calloc (n_bytes, 1);
		data.len = n_bytes;
		strncpy (data.buff, str, data.len);
	
		printf ("Writing %d bytes at 0x%lx from pid (%d)\n", data.len, data.addr, data.pid);
		printf ("Str: %s\n", data.buff);

		ioctl_n = IOCTL_WRITE_PROCESS_ADDR;
		ret = ioctl (fd, ioctl_n, &data);
		printf ("ret: %d\n", ret);
		fprintf (stderr, "ioctl err: %s\n", strerror (errno));
		break;

	case READ_PHYSICAL_ADDR:

		data.buff = (unsigned char *)calloc (n_bytes, 1);
		data.len = n_bytes;

		printf ("Reading %d bytes at 0x%lx from pid (%d)\n", data.len, data.addr, data.pid);
	
		ioctl_n = IOCTL_READ_PHYSICAL_ADDR;
		ret = ioctl (fd, ioctl_n, &data);
		printf ("ret: %d\n", ret);
		fprintf (stderr, "ioctl err: %s\n", strerror (errno));

		if (!ret) {
                        printf ("Got the state: addr: 0x%lx - value: ", data.addr);
                        for (i = 0; i < n_bytes; i++) {
                                printf (output == HEX ? HEX_FMT : CHAR_FMT, data.buff[i]);
                        }
                }
	
		break;

	case WRITE_PHYSICAL_ADDR:

		data.buff = (unsigned char *)calloc (n_bytes, 1);
		data.len = n_bytes;
		strncpy (data.buff, str, data.len);
		
		printf ("Writing %d bytes at 0x%lx from pid (%d)\n", data.len, data.addr, data.pid);
                printf ("Str: %s\n", data.buff);

                ioctl_n = IOCTL_WRITE_PHYSICAL_ADDR;
                ret = ioctl (fd, ioctl_n, &data);
                printf ("ret: %d\n", ret);
                fprintf (stderr, "ioctl err: %s\n", strerror (errno));
		break;
	
	case GET_KERNEL_MAP:
	
		ioctl_n = IOCTL_GET_KERNEL_MAP;
		ret = ioctl (fd, ioctl_n, &map_data);

		if (ret < 0) {
			fprintf (stderr, "ioctl err: %s\n", strerror (errno));
			break;
		}

		printf ("map_data.size: %d, map_data.n_entries: %d\n", map_data.size, map_data.n_entries);

		info = mmap (0, map_data.size, PROT_READ, MAP_SHARED, fd, 0);
		if (info == MAP_FAILED) {
			fprintf (stderr, "mmap err: %s\n", strerror (errno));
			break;
		}

		printf ("ret: %d\n", ret);
		fprintf (stderr, "ioctl err: %s\n", strerror (errno));

		int i, j;
		long page_size = sysconf (_SC_PAGESIZE);
        	for (i = 0; i < map_data.n_entries ; i++) {
                	struct kernel_map_info *in = &info[i];
                	printf ("start_addr: 0x%lx\n", in->start_addr);
                	printf ("end_addr: 0x%lx\n", in->end_addr);
			printf ("n_pages: %d (%ld Kbytes)\n", in->n_pages, (in->n_pages * page_size) / 1024);
			printf ("n_phys_addr: %d\n", in->n_phys_addr);
			for(j = 0; j < in->n_phys_addr; j++)
                        	printf("\tphys_addr: 0x%lx\n", in->phys_addr[j]);
			printf ("\n\n");
		}		

		if (munmap (info, map_data.size) == -1)
			perror("munmap failed\n");

		break;

	default:
		printf ("ioctl not implemented\n");
		break;
	}

	printf ("\n");
	close (fd);
	
	return 0;
}
