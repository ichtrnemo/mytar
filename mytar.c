#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "mytar.h"
#include <grp.h>
#include <pwd.h>
#include <dirent.h>
#include <unistd.h>
#include <stdint.h>
#include <utime.h>

void process_dir(char *dirName, FILE *tar);

void help(){
	printf("\n");
	printf("mytar -c archive.tar files # Create archive.tar from files\n");
	printf("mytar -x archive.tar       # Extract all files from archive.tar\n");
	printf("mytar -t archive.tar       # List all files in archive.tar\n");
	printf("\n");
}

int mypow(int n, int p){
	if(p == 0){
		return 1;
	} else if(p == 1){
		return n;
	} else {
		int res = n;
		for(int i = 2; i <= p; i++){
			res *= n;
		}
		return res;
	}
}

/* oct str to int */
int octToDec(char *size, int length){
	int res = 0;
	int pw = 0;

	for(int i = length - 2; i >= 0; i--){
		res += (size[i] - 0x30) * mypow(8, pw);
		pw++;
	}
	return res;
}

void numbersToString(uintmax_t num, char *str, int arrayLen){
	if(str == NULL){
		return;
	}

	arrayLen--;
	str[arrayLen] = '\0';
	arrayLen--;

	while(arrayLen >= 0){
		if(num != 0){
			str[arrayLen] = (char)(num % 10 + 0x30);
			num = num / 10;
		}else{
			str[arrayLen] = (char)(0x30);
		}
		arrayLen--;
	}
}

uintmax_t decimalToOctal(uintmax_t dec){
    uintmax_t oct = 0, temp = 1;

    while (dec != 0){
    	oct = oct + (dec % 8) * temp;
    	dec = dec / 8;
        temp = temp * 10;
    }

    return oct;
}

void set_uid(char *header, uid_t uid, int arrayLen){
	uintmax_t bits = decimalToOctal(uid);
	numbersToString(bits, header, arrayLen);
}

void set_gid(char *header, gid_t gid, int arrayLen){
	uintmax_t bits = decimalToOctal(gid);
	numbersToString(bits, header, arrayLen);
}

void set_size(char *header, struct stat *buff, int arrayLen){
	if(S_ISREG(buff->st_mode)){
		uintmax_t bits = decimalToOctal(buff->st_size);
		numbersToString(bits, header, arrayLen);
	} else {
		strcpy(header, "00000000000"); //dir size = 0
	}
}

void set_mtime(char *header, time_t mtime, int arrayLen){
	uintmax_t bits = decimalToOctal(mtime);
	numbersToString(bits, header, arrayLen);
}

void set_typeflag(struct posix_header *header, mode_t mode){
	if(S_ISDIR(mode)){
		header->typeflag = '5';
	} else if (S_ISREG(mode)){
		header->typeflag = '0';
	} else {
		header->typeflag = '0';
	}
}

void set_version(char *header){
	/* magic version */
	header[0] = 0x20;
	header[1] = 0x00;
}

void set_uname(char *uname, uid_t uid){
	struct passwd *pw = getpwuid(uid);
	if(pw != NULL){
		strcpy(uname, pw->pw_name);
	}
}

void set_gname(char *gname, gid_t gid){
	struct group *gr = getgrgid(gid);
	if(gr != NULL){
		strcpy(gname, gr->gr_name);
	}
}

void set_chksum(union block *header){
	size_t i;
	int unsigned_sum = 0;
	char *p;

	p = header->buffer;
	for (i = sizeof *header; i-- != 0;){
		unsigned_sum += (unsigned char) (*p++);
	}

	/* Adjust checksum to count the "chksum" field as blanks.  */

	for (i = sizeof header->header.chksum; i-- != 0;){
		unsigned_sum -= (unsigned char) header->header.chksum[i];
	}
	unsigned_sum += ' ' * sizeof header->header.chksum;
	
	char c[8];
	sprintf(c, "%06o", unsigned_sum);
	
	strcpy(header->header.chksum , c);
	header->header.chksum[6] = '\0';
	header->header.chksum[7] = ' ';
}

mode_t mode_for_file(uintmax_t mode){
	mode_t result = 0;
	/* set UID on execution */
	if(mode & TSUID){
		result = result | S_ISUID;
	}
	/* set GID on execution */
	if(mode & TSGID){
		result = result | S_ISGID;
	}
	/* read by owner */
	if(mode & TUREAD){
		result = result | S_IRUSR;
	}
	/* write by owner */
	if(mode & TUWRITE){
		result = result | S_IWUSR;
	}
	/* execute/search by owner */
	if(mode & TUEXEC){
		result = result | S_IXUSR;
	}
	/* read by group */
	if(mode & TGREAD){
		result = result | S_IRGRP;
	}
	/* write by group */
	if(mode & TGWRITE){
		result = result | S_IWGRP;
	}
	/* execute/search by group */
	if(mode & TGEXEC){
		result = result | S_IXGRP;
	}
	/* read by other */
	if(mode & TOREAD){
		result = result | S_IROTH;
	}
	/* write by other */
	if(mode & TOWRITE){
		result = result | S_IWOTH;
	}
	/* execute/search by other */
	if(mode & TOEXEC){
		result = result | S_IXOTH;
	}

	return result;
}

void set_mode(char *header, mode_t mode, int arrayLen){
	uintmax_t bits = 0;
	/* set UID on execution */
	if(mode & S_ISUID){
		bits = bits | TSUID;
	}
	/* set GID on execution */
	if(mode & S_ISGID){
		bits = bits | TSGID;
	}
	/* read by owner */
	if(mode & S_IRUSR){
		bits = bits | TUREAD;
	}
	/* write by owner */
	if(mode & S_IWUSR){
		bits = bits | TUWRITE;
	}
	/* execute/search by owner */
	if(mode & S_IXUSR){
		bits = bits | TUEXEC;
	}
	/* read by group */
	if(mode & S_IRGRP){
		bits = bits | TGREAD;
	}
	/* write by group */
	if(mode & S_IWGRP){
		bits = bits | TGWRITE;
	}
	/* execute/search by group */
	if(mode & S_IXGRP){
		bits = bits | TGEXEC;
	}
	/* read by other */
	if(mode & S_IROTH){
		bits = bits | TOREAD;
	}
	/* write by other */
	if(mode & S_IWOTH){
		bits = bits | TOWRITE;
	}
	/* execute/search by other */
	if(mode & S_IXOTH){
		bits = bits | TOEXEC;
	}

	bits = decimalToOctal(bits);
	numbersToString(bits, header, arrayLen);
}

void clean_bloc(union block *u_block){
	for(int i = 0; i < 512; i++){
		u_block->buffer[i] = 0;
	}
}

union block *make_header(char *name, struct stat *buff){
	static union block u_block;
	clean_bloc(&u_block);
	
	/* name */
	strcpy(u_block.header.name, name);
	/* mode length = 8*/
	set_mode(u_block.header.mode, buff->st_mode, 8);
	/* uid length = 8*/
	set_uid(u_block.header.uid, buff->st_uid, 8);
	/* gid length = 8*/
	set_gid(u_block.header.gid, buff->st_gid, 8);
	/* size length = 12*/
	/* size of dir = 0 */
	set_size(u_block.header.size, buff, 12);
	/* mtime length = 12 */
	set_mtime(u_block.header.mtime, buff->st_mtime, 12);
	/* typeflag length = 1 */
	set_typeflag(&u_block.header, buff->st_mode);
	/* magic length = 6 */
	strcpy(u_block.header.magic, TMAGIC);
	u_block.header.magic[5] = 0x20;
	/* version length = 2 */
	set_version(u_block.header.version);
	/* uname length = 32 */
	set_uname(u_block.header.uname, buff->st_uid);
	/* gname length = 32 */
	set_gname(u_block.header.gname, buff->st_gid);
	/* chksum length = 8*/
	set_chksum(&u_block);
	
	return &u_block;
}

int write_file_or_dir(char *name, FILE *tar){
	struct stat static buff;
	int res = stat(name, &buff);
	int r = 0;
	union block *u_block;
	char file_block[512];
	
	if(res == 0){
		u_block = make_header(name, &buff);

		/* reg file */
		if(S_ISREG(buff.st_mode)){
			FILE *file = fopen(name, "r");

			if(file == NULL){
				return -1;
			}

			fwrite(u_block->buffer, 512, 1, tar);

			while((r = fread(file_block, 1, 512, file)) == 512){
				fwrite(file_block, 512, 1, tar);
			}

			fwrite(file_block, r, 1, tar);

			for(int i = 0; i < 512; i++){//fill the rest of the side with zeros
				file_block[i] = 0;
			}

			fwrite(file_block, 512 - r, 1, tar);
			fclose(file);
			
		} else if(S_ISDIR(buff.st_mode)){/* dir (only header)*/
			fwrite(u_block->buffer, 512, 1, tar);
			process_dir(name, tar);//recursion
		}
	}
	return res;
}

void process_dir(char *dirName, FILE *tar){
	DIR *dir = NULL;
	struct dirent *entryP;
	char pathName[100];
	int len;
	
	dir = opendir(dirName);
	if(dir == NULL){
		printf("ERROR: %s can't be opened!\n", dirName);
		return;
	}

	entryP = readdir(dir);
	
	while(entryP != NULL){
		/* skip . and .. */
		if((strcmp(entryP->d_name, ".") == 0) ||
		   (strcmp(entryP->d_name, "..") == 0)){
			entryP = readdir(dir);
			continue;
		}

		/* make a path */
		strcpy(pathName, dirName);
		len = strlen(dirName);
		if(dirName[len - 1] != '/'){
			strcat(pathName, "/");
		}
		strcat(pathName, entryP->d_name);

		if(write_file_or_dir(pathName, tar) == -1){
			printf("ERROR: %s can't be opened!\n", pathName);
		}

		entryP = readdir(dir);
	}
}

void create(int argc, char **files){
	FILE *tar = fopen(files[2], "w");
	if(tar == NULL){
		printf("ERROR: target file don't open\n");
		return;
	}

	for(int i = 3; i < argc; i++){
		if(write_file_or_dir(files[i], tar) == -1){
			printf("ERROR: %s does'nt exist or can't be opened!\n", files[i]);
			return;
		}
	}
	
	/* two blocks of zeros at the end of tar */
	char z[512];
	for(int i = 0; i < 512; i++){
		z[i] = 0;
	}
	fwrite(z, 512, 1, tar);
	fwrite(z, 512, 1, tar);
	fclose(tar);
}

void extract(char *tar){
	struct stat static buff;
	union block static u_block;
	int size;

	int res = stat(tar, &buff);
	if(res != 0){
		printf("ERROR: file don't open\n");
		return;
	}

	/* dir size = 0, that is OK */	
	res = buff.st_size % 512;
	if(res != 0){
		printf("ERROR: invalid file\n");
		return;
	}

	FILE *file = fopen(tar, "r");
	if(file == NULL){
		printf("ERROR: file don't open\n");
		return;
	}

	while((res = fread(u_block.buffer, 512, 1, file)) == 1){

		if(u_block.header.typeflag == '0'){
			uid_t uid = octToDec(u_block.header.uid, 8);
			gid_t gid = octToDec(u_block.header.gid, 8);

			time_t mtime = octToDec(u_block.header.mtime, 12);

			uintmax_t uint_mode = octToDec(u_block.header.mode, 8);
			mode_t mode = mode_for_file(uint_mode);

			char filename[100];
			strcpy(filename, u_block.header.name);

			struct utimbuf new_time;

			size = octToDec(u_block.header.size, 12);
			
			FILE *out = fopen(u_block.header.name, "w");
			if(out == NULL){
				printf("ERROR: can't create file %s\n", u_block.header.name);
				break;
			}

			if(size >= 512){
				for(int i = 1; i <= size / 512; i++){
					res = fread(u_block.buffer, 512, 1, file);
					if(res == -1){
						printf("ERROR: file reading\n");
						fclose(out);
						break;
					}
					res = fwrite(u_block.buffer, 512, 1, out);
					if(res == -1){
						printf("ERROR: file writing\n");
						fclose(out);
						break;
					}
				}

				if(size % 512 != 0){
					res = fread(u_block.buffer, size % 512, 1, file);
					if(res == -1){
						printf("ERROR: file reading\n");
						fclose(out);
						break;
					}
					res = fwrite(u_block.buffer, size % 512, 1, out);
					if(res == -1){
						printf("ERROR: file writing\n");
						fclose(out);
						break;
					}
					/* offset to next entry */
					res = fseek(file, 512 - size % 512, SEEK_CUR);
					if(res == -1){
						printf("ERROR: fseek\n");
						fclose(out);
						break;
					}
				}
			}else{
				res = fread(u_block.buffer, size, 1, file);
				if(res == -1){
					printf("ERROR: file reading\n");
					fclose(out);
					break;
				}
				res = fwrite(u_block.buffer, size, 1, out);
				if(res == -1){
					printf("ERROR: file writing\n");
					fclose(out);
					break;
				}
				/* offset to next entry */
				res = fseek(file, 512 - size, SEEK_CUR);
				if(res == -1){
					printf("ERROR: fseek\n");
					fclose(out);
					break;
				}
			}

			fclose(out);
			
			/* set uid and gid for a file */
			res = chown(filename, uid, gid);
			if(res == -1){
				printf("ERROR: set uid and gid to %s\n", filename);
			}

			/* set mtime for a file */
			new_time.modtime = mtime;
			res = utime(filename, &new_time);
			if(res == -1){
				printf("ERROR: set mtime to %s\n", filename);
			}
			
			/* set mode */
			res = chmod(filename, mode);
			if(res == -1){
				printf("ERROR: set mode to %s\n", filename);
			}
			
		} else if(u_block.header.typeflag == '5'){						//dir
			uid_t uid = octToDec(u_block.header.uid, 8);
			gid_t gid = octToDec(u_block.header.gid, 8);

			time_t mtime = octToDec(u_block.header.mtime, 12);

			uintmax_t uint_mode = octToDec(u_block.header.mode, 8);
			mode_t mode = mode_for_file(uint_mode);

			struct utimbuf new_time;

			/* create dir */
			res = mkdir(u_block.header.name, mode);
			if(res == -1){
				printf("ERROR: can't create a dir %s\n", u_block.header.name);
			}

			/* set uid and gid for a file */
			res = chown(u_block.header.name, uid, gid);
			if(res == -1){
				printf("ERROR: set uid and gid to %s\n", u_block.header.name);
			}

			/* set mtime for a file */
			new_time.modtime = mtime;
			res = utime(u_block.header.name, &new_time);
			if(res == -1){
				printf("ERROR: set mtime to %s\n", u_block.header.name);
			}
		}
	}
	fclose(file);
}

void list(char *tar){
	struct stat static buff;
	union block static u_block;
	int size;

	int res = stat(tar, &buff);
	if(res != 0){
		printf("ERROR: file don't open\n");
		return;
	}

	/* dir size = 0, that is OK */	
	res = buff.st_size % 512;
	if(res != 0){
		printf("ERROR: invalid file\n");
		return;
	}

	FILE *file = fopen(tar, "r");
	if(file == NULL){
		printf("ERROR: file don't open\n");
		return;
	}

	while((res = fread(u_block.buffer, 512, 1, file)) == 1){
		if(u_block.header.typeflag == '0'){
			printf("%s\n", u_block.header.name);

			size = octToDec(u_block.header.size, 12);
			
			/* looking for an offset */
			if((size % 512) == 0){
				size = size / 512;
			} else {
				size = size / 512 + 1;
			}
			
			res = fseek(file, size * 512, SEEK_CUR);
			if(res == -1){
				printf("ERROR\n");
			}
		} else if(u_block.header.typeflag == '5'){
			printf("%s", u_block.header.name);
			size = strlen(u_block.header.name);
			if(u_block.header.name[size - 1] != '/'){
				printf("/\n");
			}else{
				printf("\n");
			}
		}
	}
	fclose(file);
}

int main(int argc, char **argv){

	if(argc > 3 && !strcmp(argv[1], "-c")){
		create(argc, argv);
	}else if(argc == 3 && !strcmp(argv[1], "-x")){
		extract(argv[2]);
	}else if(argc == 3 && !strcmp(argv[1], "-t")){
		list(argv[2]);
	}else{
		help();
	}
	return 0;
}
