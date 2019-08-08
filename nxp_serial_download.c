#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <getopt.h>
#include <time.h>

#define SPI_NOR_PAGE_SIZE 256
void usage(void)
{
	fprintf(stdout,"\nUsage: nxpflash [options] <file>\n"
                "-h             -- show this help\n"
                "-l <save log file>     -- show this help\n"
                "-p <uart path> -- show this help\n"
                "-f <firehose bootloader>          -- firehose loader\n"
                "-f <firehose bootloader>          -- firehose loader\n"
				"\n"
				"Example:\n"
				"Get Serial download status:\n"
                "	adb shell nxpflash -p /dev/ttyHSL\n"
				"Download firehose:\n"
                "	adb shell nxpflash -p /dev/ttyHSL1 -f /apps/etc/firehose.bin\n"
				"Download image:\n"
                "	adb shell nxpflash -p /dev/ttyHSL1 -f /apps/etc/firehose.bin /apps/etc/nxp_fireware.img\n"
				"Upload image:\n"
                "	adb shell nxpflash -p /dev/ttyHSL1 -f /apps/etc/firehose.bin -u 60000000 -s 100000 /apps/etc/nxp_fireware_read.img\n"
				);
	exit(-1);
	
}

#define MAX_LOG_BUF_SZ      2048
#define UNIT_MS 1000L
unsigned long long NowMS()
{

    struct timespec    tTime;

    clock_gettime(CLOCK_MONOTONIC, &tTime);

    return (((unsigned long long)tTime.tv_sec * 1000) + (unsigned long long)tTime.tv_nsec/1000000L);

}
FILE* g_LogHandle = NULL;
void SyslogOutput(const char *fmt, ...)
{
	struct timespec now;
    static char     buf[MAX_LOG_BUF_SZ];
	struct tm       *pt;
	clock_gettime(CLOCK_REALTIME, &now);
	time (&now);
	
    pt = localtime(&now.tv_sec);

	fprintf(g_LogHandle,"%04u/%02u/%02u %02u:%02u:%02u:%03u :",
                pt->tm_year + 1900, pt->tm_mon + 1, pt->tm_mday,
                pt->tm_hour, pt->tm_min, pt->tm_sec,now.tv_nsec/1000000L);
				
    va_list     ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
	fprintf(g_LogHandle,"%s",buf);

}
void SyslogOutputRaw(const char *fmt, ...)
{
    static char     buf[MAX_LOG_BUF_SZ];

    va_list     ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
	fprintf(g_LogHandle,"%s",buf);

}
int read_uart(int tty,char* response, int response_length)
{
	unsigned long long time_start, time_end;
	int off = 0;
	int ret;
	
	time_start = NowMS();
	off = 0;
	while(off < response_length)
	{
		ret = read(tty,response+off,response_length - off);
		if (ret < 0)
		{
			time_end = NowMS();
			if(time_end > time_start + 2*UNIT_MS)
			{
				SyslogOutput("SyslogOutput:read time out time_start %lld %lld\n",time_start,time_end);
				return -2;
			}
			// SyslogOutput("SyslogOutput:read time_start %lld %lld continue\n",time_start,time_end);
			continue;
		}
		
		
		off += ret;
	}
	return response_length;
}
int read_line(int tty, char* line,int max_size)
{
	int offset = 0;
	char ch;
	int ret;
	while(offset < max_size-1)
	{
		ret = read_uart(tty,&ch,1);
		if(ret<0)
		{
			line[offset] = 0;
			return -1;
		}
		if(ch == '\r' || ch == '\n')
		{
			line[offset] = 0;
			return offset;
		}
		line[offset++]=ch; 
	}
	line[offset] = 0;
	return offset;
}

int write_uart(int tty,char* buffer, int length)
{
	unsigned long long time_start, time_end;
	int off = 0;
	int ret;
	
	off = 0;
	while(off < length)
	{
		ret = write(tty,&buffer[off],length - off);
		if (ret <= 0)
		{
			SyslogOutput("write_cmd:write fail off %d %d\n",off,ret);
			continue;
		}
		
		off += ret;
	}
	tcdrain(tty);
	return length;
}
int write_cmd(int tty,char* cmd, int size, char* response, int response_length)
{
	int ret;
	int i = 0;
	int print_size = size > 10?10:size;
	SyslogOutput("write_cmd:write cmd  size %d\n",size);
	for(i = 0; i< print_size;i++)
	{
		SyslogOutputRaw("%02x ",cmd[i]);
	}
	SyslogOutputRaw("\n");
	ret = write_uart(tty,cmd, size);
	
	if(response && response_length)
	{
		ret = read_uart(tty,response, response_length);
	}
	return ret;
	
}
char GET_STATUS[]	={0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
char READ_MEMORY[]	={0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
char WRITE_MEMORY[]	={0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
char WRITE_FILE[]	={0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 

static unsigned run_get_status(int tty, unsigned int* res)
{
	unsigned int response[2];
	int result = 0;
	result = write_cmd(tty,GET_STATUS,sizeof(GET_STATUS),(char*)&response,sizeof(response));
	if(res)
	{
		*res = response[0];
	}
	SyslogOutput("run_get_status result %d response %x  %x\n",result,response[0],response[1]);
	return result;
}
void bigEndFill(int value, char* array)
{
	array[0] = (char)((value>>24)&0xFF);
	array[1] = (char)((value>>16)&0xFF);
	array[2] = (char)((value>>8)&0xFF);
	array[3] = (char)((value>>0)&0xFF);
}
#define ACK_ENG   0x56787856 /* VxxV '56 78 78 56'  */
#define ACK_PROD  0x12343412 /* '12 34 34 12' */
static int run_write_file(int tty, const char* fileName, unsigned int addr, unsigned int* res)
{
	unsigned int response[2];
	int result = 0;
	int length = 0;
	int read_nb = 0;
	char WRITE_FILE[]	={0x04, 0x04, 
							0x00, 0x00, 0x00, 0x00, //address
							0x00, 
							0x00, 0x00, 0x00, 0x00, // size
							0x00, 0x00, 0x00, 0x00, 
							0x00};  //APP_TYPE
	char buffer[1024];
	unsigned int size = 0;
	FILE* fd = fopen(fileName,"rb");
	if(!fd){
		
		SyslogOutput("run_write_file open %s fail\n",fileName);
		return -1;
	}
	
	fseek(fd, 0, SEEK_END);
	size = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	
	bigEndFill(addr,&WRITE_FILE[2]);
	bigEndFill(size,&WRITE_FILE[7]);
	
	SyslogOutput("run_write_file %s size 0x%x\n",fileName,size);
	
	
	result = write_cmd(tty,WRITE_FILE,sizeof(WRITE_FILE),NULL,0);
	if(result < 0)
	{
		SyslogOutput("run_write_file Failed to write_cmd %d\n",result);
		return result;
	}
	
	read_nb = 0;
	while(read_nb < size)
	{
	 length = fread(buffer, 1, sizeof(buffer), fd);
	 if(length <=0 )
	 {
		 SyslogOutput("WARNING:run_write_file fread read_nb %d read %d\n",read_nb,length);
		 return -3;
	 }
	 
	 result = write_uart(tty,buffer,length);
	 read_nb += length;
	}
	result = read_uart(tty,response, sizeof(response));
	
	SyslogOutput("run_write_file response 0x%x 0x%x\n",response[0],response[1]);
	if(response[0] != ACK_ENG && ACK_PROD != response[0])
	{
		SyslogOutput("run_write_file WRITE_FILE response 0x%x 0x%x  wrong\n",response[0],response[1]);
		fclose(fd);
		return -2;
	}
	return result;
}

static int run_jump_address(int tty, unsigned int addr, unsigned int* res)
{
	int response[2];
	int result;
	char JUMP[]	={0x0b, 0x0b, 
							0x00, 0x00, 0x00, 0x00, //address
							0x00, 
							0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00, 
							0x00}; 
	bigEndFill(addr,&JUMP[2]);
	result = write_cmd(tty,JUMP,sizeof(JUMP),(char*)&response,sizeof(response));
	SyslogOutput("run_jump_address result %d response %x %x\n",result,response[0],response[1]);
	
	
	return result;
}
static int UartOpen(const char* ttyPath)
{
		struct termios tio;
		int tty_fd = 0;

        tty_fd=open(ttyPath, O_RDWR | O_NONBLOCK);
		if(tty_fd < 0)
			return tty_fd;
		
		memset(&tio,0,sizeof(tio));
        tio.c_iflag=0;
        tio.c_oflag=0;
        tio.c_cflag=CS8|CREAD|CLOCAL;           // 8n1, see termios.h for more information
        tio.c_lflag=0;
        tio.c_cc[VMIN]=1;
        tio.c_cc[VTIME]=5;
		
        cfsetospeed(&tio,B115200);            // 115200 baud
        cfsetispeed(&tio,B115200);            // 115200 baud
		tcsetattr(tty_fd,TCSANOW,&tio);
		
		return tty_fd;
}
/**
 * Download firehose loaderto RAM by serial
 * @param[in] tty serial handle.
 * @param[in] firehose the firehose file path.
 * @param[in] addr the ram address.
 * @param[in] jumpAddr the firehose IV table position.
 * @retval 0 SUCEESS.
 */
int download_firehose(int tty, unsigned int addr,char* firehose,unsigned int jumpAddr)
{
	int result = 0;
	unsigned int response = 0;
	
	SyslogOutput("download_firehose addr %x %s \n",addr,firehose);
	
	result = run_get_status(tty,&response);
	if(result < 0)
	{
		SyslogOutput("download_firehose run_get_status fail %d\n",result);
		return result;
	}
	result = run_write_file( tty, firehose, addr, &response);
	SyslogOutput("download_firehose write addr %x %s finish result %d\n",addr,firehose,result);
	if(result < 0)
	{
		SyslogOutput("download_firehose run_write_file fail %d\n",result);
		return result;
	}
	result =  run_jump_address( tty,jumpAddr,&response);
	
	SyslogOutput("download_firehose jump addr %x  finish result %d\n",jumpAddr,result);
	return result;
}


int send_cmd_and_wait_ack(int tty,char* cmd, int wait_nb)
{
	char line[256];
	int read_nb = 0;
	int time_out_count = 0;
	int cmd_size = strlen(cmd);
	write_cmd(tty,cmd,cmd_size,0,0);
	SyslogOutput("send_cmd_and_wait_ack cmd %s\n",cmd);
	while(1)
	{
		read_nb = read_line(tty,line,sizeof(line));
		if(read_nb < 0 && time_out_count > wait_nb) // read time out
		{
			
			SyslogOutput("send_cmd_and_wait_ack cmd %s  time out\n",cmd);
			return -1;
		}
		else if (read_nb < 0)
		{
			time_out_count++;
			continue;
		}
		if(read_nb == 2 && strcmp(line,"ok") == 0)
		{
			SyslogOutput("send_cmd_and_wait_ack cmd %s  response success\n",cmd);
			return 0;
		}
		else if (read_nb == 4 && strcmp(line,"fail") == 0)
		{
			SyslogOutput("send_cmd_and_wait_ack cmd %s  response fail\n",cmd);
			return -2;
		}
		else {
			SyslogOutput("firehose:%s\n",line);
			
		}	
		
	}
	
}
int send_data_and_wait_ack(int tty,char* data, int data_size)
{
	char line[256];
	int read_nb = 0;
	int time_out_count = 0;
	int length;
	length = sprintf(line,"data %x\n",data_size);
	SyslogOutput("send_data_and_wait_ack data_size %d\n",data_size);
	write_cmd(tty,line,length,0,0);
	write_cmd(tty,data,data_size,0,0);
	
	while(1)
	{
		read_nb = read_line(tty,line,sizeof(line));
		if(read_nb < 0 && time_out_count > 1) // read time out
		{
			
			SyslogOutput("send_data_and_wait_ack  time out\n");
			return -1;
		}
		else if (read_nb < 0)
		{
			time_out_count++;
			continue;
		}
		if(read_nb == 2 && strcmp(line,"ok") == 0)
		{
			SyslogOutput("send_data_and_wait_ack   response success\n");
			return 0;
		}
		else if (read_nb == 4 && strcmp(line,"fail") == 0)
		{
			SyslogOutput("send_data_and_wait_ack response fail\n");
			return -2;
		}
		else {
			SyslogOutput("firehose:%s\n",line);
			
		}	
		
	}
	
}
/**
 * Upload ram to file by serial
 * @param[in] tty serial handle.
 * @param[in] filename the save file path.
 * @param[in] addr the ram address.
 * @param[in] size the read ram size.
 * @retval the read ram size.
 */
int upload_image(int tty,const char* filename,unsigned int addr,unsigned int size)
{
	FILE* fd;
	char line[256];
	int read_nb;
	int offset = 0;
	int rety = 0;
	int ret;
	SyslogOutput("upload_image filename %s  download_addr 0x%x size 0x%x\n",filename,addr,size);
	fd = fopen(filename,"wb");
	if(!fd)
	{
		SyslogOutput("upload_image open filename %s  fail\n",filename);
		return -1;
	}
	while(rety++ < 5){
		ret = send_cmd_and_wait_ack(tty,"ping\n",0);
		if(ret == 0)
			break;
	}
	if(ret != 0 )
	{
		SyslogOutput("upload_image communicate with firehose fail\n");
		return -1;
	}
	ret = sprintf(line,"read %x,%x\n",addr,size);
	write_cmd(tty,line,ret,0,0);
	
	// wait Read 0x<size> from address 0x<addr>
	while(1)
	{
		read_nb = read_line(tty,line,sizeof(line));
		if(read_nb < 0)
		{
			SyslogOutput("upload_image read  fail\n");
			return -1;
		}
		SyslogOutput("firehose %s\n",line);
		if(read_nb > 7 && 0 == strncmp(line,"Read 0x",7))
		{
			break;
		}
		
	}
	read_nb = read_uart(tty,line,1);
	if(read_nb < 0)
	{
		SyslogOutput("upload_image read  fail 1\n");
		return -2;
	}
	if(line[0] == '\n')
	{
		SyslogOutput("upload_image skip CR\n");
	}
	offset = 0;
	while(offset < size)
	{
		if(size - offset > sizeof(line))
		{
			read_nb = read_uart(tty,line,sizeof(line));
		}
		else 
		{
			read_nb = read_uart(tty,line,size - offset);
		}
		if(read_nb < 0)
		{
			SyslogOutput("upload_image read  fail 1\n");
			return -3;
		}
		fwrite(line,1,read_nb,fd);
		
		offset += read_nb;
	}
	
	
	read_nb = read_line(tty,line,sizeof(line));
	if(read_nb < 0)
	{
		SyslogOutput("upload_image read  fail\n");
		return -1;
	}
	SyslogOutput("firehose %s\n",line);
	fclose(fd);
	SyslogOutput("upload_image finish\n");
	
	return 0;
}
/**
 * Download image to flash by serial
 * @param[in] tty serial handle.
 * @param[in] filename the image file path.
 * @retval 0 For Success.
 * @retval other For Failures.
 */
int download_image(int tty,const char* filename)
{
	char line[256];
	int ret = 0;
	int rety = 0;
	FILE* fd = NULL;
	size_t file_size;
	char buffer[SPI_NOR_PAGE_SIZE];
	int read_nb;
	int length;
	SyslogOutput("download_image filename %s  \n",filename);
	
	fd = fopen(filename,"rb");
	fseek(fd, 0, SEEK_END);
	file_size = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	
	if(!fd )
	{
		SyslogOutput("download_image open  %s fail\n",filename);
		return  -1;
	}
	
	while(rety++ < 5){
		ret = send_cmd_and_wait_ack(tty,"ping\n",0);
		if(ret == 0)
			break;
	}
	if(ret != 0 )
	{
		SyslogOutput("download_image communicate with firehose fail\n");
		return -1;
	}
	// read flash vendor
	ret = send_cmd_and_wait_ack(tty,"status\n",5); 
	if(ret != 0 )
	{
		SyslogOutput("download_image status cmd fail\n");
		return -2;
	}
	
	// erase all flash
	ret = send_cmd_and_wait_ack(tty,"erase all\n",10); 
	if(ret != 0 )
	{
		SyslogOutput("download_image erase all flash fail\n");
		return -2;
	}
	
	read_nb = 0;
	while(read_nb < file_size)
	{
		 length = fread(buffer, 1, sizeof(buffer), fd);
		 if(length <=0 )
		 {
			 SyslogOutput("WARNING:download_image fread read_nb %d read %d\n",read_nb,length);
			 return -3;
		 }
		if(length < sizeof(buffer)) // fill remained with 0xFF 
		{
			 memset(&buffer[length],0xFF,sizeof(buffer) - length);
		}
		// send one page data
		ret = send_data_and_wait_ack(tty,buffer,sizeof(buffer));
		if(ret != 0 )
		{
			SyslogOutput("download_image erase all flash fail\n");
			return -3;
		}
		// write data to flash
		sprintf(line,"write %x\n",read_nb);
		ret = send_cmd_and_wait_ack(tty,line,1); 
		if(ret != 0 )
		{
			SyslogOutput("download_image erase all flash fail\n");
			return -2;
		}
		read_nb += length;
	}
	SyslogOutput("download_image Finish\n");
	fclose(fd);
	return 0;
}

int main(int argc,char** argv)
{
        
        char* firehose = NULL;
        int tty_fd;
		char *filename = NULL;
        int c; 
		char *ttyPath = NULL;
		char* logFile = NULL;
		unsigned int download_addr=0x20000000;
		unsigned int jump_addr=    0x20001000;
		int option_index = 0;
		int result = 0;
		int upload_size = 0;
		int upload_addr = 0x60000000;
		g_LogHandle = stderr; // initial log handle
		
		while ((c = getopt_long(argc, argv, "hu:a:f:l:p:j:s:", NULL, &option_index)) != -1) 
		{
			switch (c) 
			{
				case 'h':
					usage();
				break;
				case 'u':
					upload_addr=strtol(optarg, NULL, 16);;
					break;
				case 's':
					upload_size=strtol(optarg, NULL, 16);
					break;
				case 'f':
					firehose = (char*) calloc(1, 128);
					if (firehose == NULL) {
						SyslogOutput("Failed to allocate firehose!");
						return -1;
					}
					strncpy(firehose, optarg, 127);
					break;
				case 'p':
					ttyPath = (char*) calloc(1, 128);
					if (ttyPath == NULL) {
						SyslogOutput("Failed to allocate ttyPath!");
						return -1;
					}
					strncpy(ttyPath, optarg, 127); 
					break;
				case 'l':
					g_LogHandle = fopen(optarg,"w");
					if(g_LogHandle == NULL)
						g_LogHandle = stderr;
					break;
				case 'j':
					jump_addr = strtol(optarg, NULL, 16);
					break;
				case 'a':
					download_addr = strtol(optarg, NULL, 16);
					break;
				default:
				break;
			}
        }
		
		filename = (char*) calloc(1, 128);
		if (filename == NULL) {
			SyslogOutput("Failed to allocate filename!");
			return -1;
		}
		
		
		if(!ttyPath)
		{
			usage();
		}
		tty_fd = UartOpen(ttyPath);
		if(tty_fd < 0)
		{
			SyslogOutput("open %s fail\n",ttyPath);
			return -3;
		}
		if(run_get_status(tty_fd,NULL) <= 0)
		{
			SyslogOutput("Get status fail\n");
			return -2;
		}
		
		if(!firehose && upload_size == 0)
		{
			return 0; //just query status
		}
		SyslogOutput("ttyPath %s\n",ttyPath?ttyPath:"NULL");
		SyslogOutput("firehose %s\n",firehose?firehose:"NULL");
		SyslogOutput("jump_addr %x\n",jump_addr);
		SyslogOutput("download_addr %x\n",download_addr);
		
		
		
		if(!firehose)
		{  
			return -2;
		}
		// download firehose first.
		result = download_firehose(tty_fd,download_addr,firehose,jump_addr);
		SyslogOutput("download_firehose %d\n",result);
		
		if (optind > argc - 1) {
		    free(filename); // do nothing since not input upload or download image path,
			return 0;
		} else {
		   memset(filename,0,128);
		   strncpy(filename, argv[optind++], 127);
		}
        SyslogOutput("Image file: %s\n",filename);
		
		if(upload_size) // upload case
		{
			upload_image(tty_fd,filename,upload_addr,upload_size);
		}
		else // download case, it is need download firehose first
		{
			download_image(tty_fd, filename);
		}
        close(tty_fd);

        return EXIT_SUCCESS;
}