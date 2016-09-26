#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include <stdbool.h>
#include "filesys/filesys.h"
#include "userprog/process.h"
#include <threads/synch.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "threads/malloc.h"

struct fd_elem
{
	struct file *file;
	int fd;
	struct list_elem elem;
};

#define ERROR -1
#define STDIN 0
#define STDOUT 1
#define MAX_FILE_NAME_LENGTH 14

struct lock lock;		//system call lock TODO:new code
struct file *findbyFD(int fd, bool delete);
//unsigned tell (int fd);

/*READ AND WRITE USER MEMORY*/
static int get_user (const uint8_t *uaddr);
static uint32_t get_user_int(const uint8_t* uaddr);
static char* get_user_string(const uint8_t* uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

/**SYSTEM CALLS**/
void halt(void);
void exit (int status);
tid_t exec (const char *cmd_line);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int insertFile_fd(struct file *file);
int read (int fd, void *buffer, unsigned size);
int filesize (int fd);
int open (const char *file);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/*helper methods*/
int checkFileNameLength(const char* file);

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
/*
printf("system call!");
thread_exit();
*/
  uint32_t* stack_ptr = f->esp;
  uint32_t syscallNumber = get_user_int((uint8_t*)stack_ptr);
  //printf("syscall number: %d", syscallNumber);
  uint32_t intArg, intArg2;
  void* voidArg;
  char* stringArg;
  switch(syscallNumber) {
  	case SYS_HALT:
		halt();
		break; //not reached
	case SYS_EXIT:
		intArg = get_user_int((uint8_t*)(stack_ptr+1));
		exit(intArg);
		break; //not reached
	case SYS_EXEC:
		stringArg = get_user_string((uint8_t*)(stack_ptr+1));
		f->eax = (uint32_t)exec(stringArg);
		break;
	case SYS_WAIT:
		intArg = (tid_t)get_user_int((uint8_t*)(stack_ptr+1));
		f->eax = (uint32_t)wait(intArg);
		break;
	case SYS_CREATE:
		stringArg = get_user_string((uint8_t*)(stack_ptr+1));
		intArg = get_user_int((uint8_t*)(stack_ptr+2));
		f->eax = (uint32_t)create(stringArg, intArg);
		break;
	case SYS_REMOVE:
		stringArg = get_user_string((uint8_t*)(stack_ptr+1));
		f->eax = (uint32_t)remove(stringArg);
		break;
	case SYS_WRITE:
		intArg = get_user_int((uint8_t*)(stack_ptr+1));
		voidArg = (void*)get_user_int((uint8_t*)(stack_ptr+2));
		intArg2 = get_user_int((uint8_t*)(stack_ptr+3));
		f->eax = (uint32_t)write(intArg, voidArg, intArg2);
		break;
	/*case SYS_OPEN:
		stringArg = get_user_string((uint8_t*)(stack_ptr+1));
		f->eax = (uint32_t)open(stringArg);
		break;
	case SYS_FILESIZE:
		intArg = get_user_int((uint8_t*)(stack_ptr+1));
		f->eax = (uint32_t)filesize(intArg);
		break;
	case SYS_READ:
		intArg = get_user_int((uint8_t*)(stack_ptr+1));
		voidArg = get_user_int((uint8_t*)(stack_ptr+2));
		intArg2 = get_user_int((uint8_t*)(stack_ptr+3));
		f->eax = (uint32_t)read(intArg, voidArg, intArg2);
		break;
	case SYS_WRITE:
		intArg = get_user_int((uint8_t*)(stack_ptr+1));
		voidArg = get_user_int((uint8_t*)(stack_ptr+2));
		intArg2 = get_user_int((uint8_t*)(stack_ptr+3));
		f->eax = (uint32_t)write(intArg, voidArg, intArg2);
		break;
	case SYS_SEEK:
		intArg = get_user_int((uint8_t*)(stack_ptr+1));
		intArg2 = get_user_int((uint8_t*)(stack_ptr+2));
		seek(intArg, intArg2);
		break;
	case SYS_TELL: 
		intArg = get_user_int((uint8_t*)(stack_ptr+1));
		f->eax = (uint32_t)tell(intArg);
		break;
	case SYS_CLOSE:
		intArg = get_user_int((uint8_t*)(stack_ptr+1));
		close(intArg);
		break;*/
  }
}

/* Reads a byte at user virtual address UADDR. UADDR must be below PHYS_BASE. Returns the byte value if successful, -1 if a segfault occurred. */ 
static int get_user (const uint8_t *uaddr) {
 	int result; 	
	asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr)); 
	return result; 
}

static uint32_t get_user_int(const uint8_t* uaddr) {
	const uint8_t* uaddr_ptr = uaddr;
	uint32_t i;
	for(i = 0; i < sizeof(uint32_t); i++)
	{
		if(is_user_vaddr(uaddr_ptr) == 0 || get_user(uaddr_ptr) == -1)
		{
			exit(1);
		}
		uaddr_ptr++;
	}
	return *((uint32_t*)uaddr);
} 

static char* get_user_string(const uint8_t* uaddr) {
	int safeReadData;	
	const uint8_t* uaddr_ptr = uaddr;
 	// there must be a better way of doing this without repeating code
	if(is_user_vaddr(uaddr) == 0)
	{
		exit(1);
	} 
	while((safeReadData = get_user(uaddr_ptr)))
	{
		if(safeReadData == -1)
		{
			exit(1);
		}
		uaddr_ptr++;
		if(is_user_vaddr(uaddr_ptr) == 0)
		{
			exit(1);
		} 
	}
	return (char*)uaddr;
}

/* Writes BYTE to user address UDST. UDST must be below PHYS_BASE. Returns true if successful, false if a segfault occurred. */ 
static bool put_user (uint8_t *udst, uint8_t byte) { 
	int error_code; 
	asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte)); 	return error_code != -1;
}

void halt(void) {
  /*
  Terminates Pintos by calling shutdown_power_off() (declared in ‘devices/shutdown.h’). This   should be seldom used, because you lose some information about possible deadlock situations, etc.*/
  shutdown_power_off();
}

void exit (int status) {
  /*Terminates the current user program, returning status to the kernel. If the process’s parent waits for it(see below), this is the status that will be returned. Conventionally, a status of 0 indicates success and nonzero values indicate errors. */
  //notifyParent(status);
  thread_exit();
}

tid_t exec (const char *cmd_line) {
  /*Runs the executable whose name is given in cmd line, passing any given arguments, and returns the new process’s program id (pid). Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this. */
	/*char* cmd_ptr = get_user_string((uint8_t*)cmd_line);
	printf(cmd_line);
	lock_acquire(&filesys_lock);
	tid_t child_tid = process_execute(cmd_ptr);
	lock_release(&filesys_lock);
	if(child_tid == TID_ERROR)
	{
		return TID_ERROR;
	}
	addChildProcess(child_tid);
	return child_tid;*/
	//return TID_ERROR;
}

int wait (tid_t pid) {
  /*Waits for a child process pid and retrieves the child’s exit status. If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit. If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes that have already terminated by the time the parent calls wait, but the kernel must still allow the parent to retrieve its child’s exit status, or learn that the child was terminated by the kernel. wait must fail and return -1 immediately if any of the following conditions is true: • pid does not refer to a direct child of the calling process. pid is a direct child of the calling process if and only if the calling process received pid as a return value from a successful call to exec. Note that children are not inherited: if A spawns child B and B spawns child process C, then A cannot wait for C, even if B is dead. A call to wait(C) by process A must fail. Similarly, orphaned processes are not assigned to a new parent if their parent process exits before they do. • The process that calls wait has already called wait on pid. That is, a process may wait for any given child at most once. Processes may spawn any number of children, wait for them in any order, and may even exit without having waited for some or all of their children. Your design should consider all the ways in which waits can occur. All of a process’s resources, including its struct thread, must be freed whether its parent ever waits for it or not, and regardless of whether the child exits before or after its parent. You must ensure that Pintos does not terminate until the initial process exits. The supplied Pintos code tries to do this by calling process_wait() (in ‘userprog/process.c’) from main() (in ‘threads/init.c’). We suggest that you implement process_wait() according to the comment at the top of the function and then implement the wait system call in terms of process_wait(). Implementing this system call requires considerably more work than any of the rest. */
}

bool create (const char *file, unsigned initial_size) {
  /*Creates a new ﬁle called ﬁle initially initial size bytes in size. Returns true if successful, false otherwise. Creating a new ﬁle does not open it: opening the new ﬁle is a separate operation which would require a open system call.*/
  
  if(checkFileNameLength(file) < 0)
  {
	return false;
  }
  //file size is unchecked. need to look up if we need to enforce a limit
  lock_acquire(&filesys_lock);
  filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return true;
}

bool remove (const char *file) {
  /*Deletes the ﬁle called ﬁle. Returns true if successful, false otherwise. A ﬁle may be removed regardless of whether it is open or closed, and removing an open ﬁle does not close it. See [Removing an Open File], page 35, for details.*/
  if(checkFileNameLength(file) < 0)
  {
	return false;
  }
  lock_acquire(&filesys_lock);
  filesys_remove(file);
  lock_release(&filesys_lock);
  return true;
}

int checkFileNameLength(const char* file){
	int i;
	for(i = 0; i <= MAX_FILE_NAME_LENGTH; i++) // <= if file name length doesn't include '\0'
	{
		if(file[i] == '\0')
		{
			return i;//length
		}
	}
	return -1;
}

/*Opens the ﬁle called ﬁle. Returns a nonnegative integer handle called a “ﬁle descriptor” (fd), or -1 if the ﬁle could not be opened.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output. The open system call will never return either of these ﬁle descriptors, which are valid as system call arguments only as explicitly described below.
Each process has an independent set of ﬁle descriptors. File descriptors are not inherited by child processes.
When a single ﬁle is opened more than once, whether by a single process or diﬀerent processes, each open returns a new ﬁle descriptor. Diﬀerent ﬁle descriptors for a single ﬁle are closed independently in separate calls to close and they do not share a ﬁle position.
*/

int open (const char *file){		//what if it's already open??
	int fd = ERROR;
	if(file == NULL || !is_user_vaddr(file))		//Check if valid address
	{
		 return fd;
	}

	lock_acquire(&lock);
	struct file *openedFile = filesys_open(file);
	if(openedFile)		//file successfully opened
	{
		fd = insertFile_fd(openedFile);

	}else		//open unsuccessful
	{
		fd = ERROR;		//TODO: Kills process
	}
	lock_release(&lock);
	return fd;
}


/*Returns the size, in bytes, of the ﬁle open as fd.
*/
int filesize (int fd){
	int size = 0;
	lock_acquire(&lock);
	struct file *openedfile = findbyFD(fd, 0);
	if(!openedfile)
	{
		int size = file_length(openedfile);
	}
	lock_release(&lock);
	return size;
}


/*Reads size bytes from the ﬁle open as fd into buﬀer. Returns the number of bytes actually read (0 at end of ﬁle), or -1 if the ﬁle could not be read (due to a condition other than end of ﬁle). Fd 0 reads from the keyboard using input_getc().
*/
int read (int fd, void *buffer, unsigned size)
{
	unsigned bytesread = 0;
	if(buffer == NULL || !is_user_vaddr(buffer))		//Check if valid address
	{
		thread_exit() ;		//TODO: error, kill the process
	}

	if(fd == STDIN)
	{
		unsigned i;
		char *buff = buffer;
	      for (i = 0; i < size; i++)
		{
		  buff[i] = input_getc();
		}
	      bytesread = i;
	}else if(fd == STDOUT)
	{

	}else
	{
		lock_acquire(&lock);
		struct file *file = findbyFD(fd, 0);
		bytesread = file_read(file, buffer, size);
		lock_release(&lock);
	}
	return bytesread;
}


/*Writes size bytes from buﬀer to the open ﬁle fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-ﬁle would normally extend the ﬁle, but ﬁle growth is not imple-mented by the basic ﬁle system. The expected behavior is to write as many bytes as possible up to end-of-ﬁle and return the actual number written, or 0 if no bytes could be written at all.
Fd 1 writes to the console. Your code to write to the console should write all of buﬀer
in one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buﬀers.) Otherwise, lines of text output by diﬀerent processes may end up interleaved on the console, confusing both human readers and our grading scripts.
*/
int write (int fd, const void *buffer, unsigned size){
	int byteswritten = 0;
	if(buffer == NULL || !is_user_vaddr(buffer) || fd == STDIN)		//Check if valid user address and not STDIN
	{
		thread_exit();
	}
	else if(fd == STDOUT)
	{
		lock_acquire(&lock);
		char *buff = buffer;
		putbuf(buffer, size); 
		lock_release(&lock);
		/*lock_acquire(&lock);
		if(size > 500)
		{
			int numwrites = size/500;
			int leftover = size%500;
			char *buff = buffer;
			int i = 0;
			for(int k=0; k<numwrites;k++)
			{
				putbuf(&buff[i], 500);
				i+=500;
			}
			putbuf(&buff[i],leftover);
		}
		lock_release(&lock);
		byteswritten = size;*/
	}
	else
	{
		struct file *file = findbyFD(fd, 0);
		if(file != NULL)
		{
			lock_acquire(&lock);
			byteswritten = file_write(file, buffer, size);
			lock_release(&lock);
		}
	}
	return byteswritten;
}


/*Changes the next byte to be read or written in open ﬁle fd to position, expressed in bytes from the beginning of the ﬁle. (Thus, a position of 0 is the ﬁle’s start.)
A seek past the current end of a ﬁle is not an error. A later read obtains 0 bytes, indicating end of ﬁle. A later write extends the ﬁle, ﬁlling any unwritten gap with zeros. (However, in Pintos ﬁles have a ﬁxed length until project 4 is complete, so writes past end of ﬁle will return an error.) These semantics are implemented in the ﬁle system and do not require any special eﬀort in system call implementation.
*/
void seek (int fd, unsigned position){
	  lock_acquire(&lock);
	  struct file *file = findbyFD(fd, 0);
	  if (file == NULL)
	    {
	      lock_release(&lock);
	      return;
	    }
	  file_seek(file, position);
	  lock_release(&lock);
}


/*Returns the position of the next byte to be read or written in open ﬁle fd, expressed in bytes from the beginning of the ﬁle.*/
unsigned tell (int fd){
	unsigned offset = 0;
	 lock_acquire(&lock);
	 struct file *file = findbyFD(fd, 0);
	 if (file == NULL)
	   {
	     lock_release(&lock);
	     return ERROR;
	   }
	offset = file_tell(file);
	lock_release(&lock);
	return offset;
}

/*Closes ﬁle descriptor fd. Exiting or terminating a process implicitly closes all its open ﬁle descriptors, as if by calling this function for each one.*/
void close (int fd){
	  lock_acquire(&lock);
	  struct file *file = findbyFD(fd, 1);
	  lock_release(&lock);
}




struct file *findbyFD(int fd, bool delete){

	struct thread *t = thread_current();
	struct list *currlist = t->fileDirectory;
    struct list_elem *e;

    for (e = list_begin (currlist); e != list_end (currlist);		//find file with fd
         e = list_next (e))
      {
        struct fd_elem *currelem = list_entry (e, struct fd_elem, elem);
        if(currelem->fd == fd)
        {
        	if(delete)
        	{
        		file_close(currelem->file);
        		list_remove(&(currelem->elem));
        		free(currelem);
        		return NULL;
        	}else
        	{
        		return currelem->file;
        	}
        }
      }
    return NULL;
}



/*gets the fd of a file in a current running thread. If file not in fd list of thread, then
 * inserts it
 */
int insertFile_fd(struct file *file){
	struct thread *t = thread_current();
	struct list *fd_list = t->fileDirectory;

	if(fd_list == NULL)		//initialize the fd list of thread if empty
	{
		fd_list = malloc(sizeof(struct list));
		list_init (fd_list);
	}

	struct fd_elem *insertFile = malloc(sizeof(struct fd_elem));		//init file list element
	insertFile->fd = t->nextfdnum;
	insertFile->file = file;
	t->nextfdnum +=1;		//set up the fd num for the next file
	list_push_back(fd_list, &(insertFile->elem));
	return insertFile->fd;

}

