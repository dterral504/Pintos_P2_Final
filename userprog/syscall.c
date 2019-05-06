#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "lib/log.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"

#define LOGGING_LEVEL 6
#define DEBUG true
#define USER_VADDR_END ((void *)0x08048000)

// ***** function declarations *****
// *********************************
static void syscall_handler(struct intr_frame *);
// syscall function delclarations
static void sys_halt();
static void sys_exit(struct intr_frame *f);
static void sys_exec(struct intr_frame *f);
static void sys_wait(struct intr_frame *f);
static void sys_create(struct intr_frame *f);
static void sys_remove(struct intr_frame *f);
static void sys_open(struct intr_frame *f);
static void sys_filesize(struct intr_frame *f);
static void sys_read(struct intr_frame *f);
static void sys_write(struct intr_frame *f);
static void sys_seek(struct intr_frame *f);
static void sys_tell(struct intr_frame *f);
static void sys_close(struct intr_frame *f);
// syscall helper functions
static struct fd_list_elem *find_file(int fd);
void check_stack_pointer(struct intr_frame *f, int num_args);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  // check for valid stack pointer
  if ((f->esp) >= PHYS_BASE)
    thread_exit();
  else if (!pagedir_get_page(thread_current()->pagedir, f->esp))
    thread_exit();

  // add stdin and stdout to fd_list
  struct fd_list_elem *stdin;
  struct fd_list_elem *stdout;
  if (list_empty(&thread_current()->fd_list))
  { // list_empty ensures this only happens the first syscall
    stdin = malloc(sizeof(struct fd_list_elem));
    stdin->fd = STDIN_FILENO;
    list_push_back(&thread_current()->fd_list, &stdin->file_elem);
    stdout = malloc(sizeof(struct fd_list_elem));
    stdout->fd = STDOUT_FILENO;
    list_push_back(&thread_current()->fd_list, &stdout->file_elem);
  }

  switch (*(int *)f->esp)
  {
  case SYS_HALT:
  {
    sys_halt();
    break;
  }
  case SYS_EXIT:
  {
    sys_exit(f);
    break;
  }
  case SYS_EXEC:
  {
    sys_exec(f);
    break;
  }
  case SYS_WAIT:
  {
    sys_wait(f);
    break;
  }
  case SYS_CREATE:
  {
    sys_create(f);
    break;
  }
  case SYS_REMOVE:
  {
    sys_remove(f);
    break;
  }
  case SYS_OPEN:
  {
    sys_open(f);
    break;
  }
  case SYS_FILESIZE:
  {
    sys_filesize(f);
    break;
  }
  case SYS_READ:
  {
    sys_read(f);
    break;
  }
  case SYS_WRITE:
  {
    sys_write(f);
    break;
  }
  case SYS_SEEK:
  {
    sys_seek(f);
    break;
  }
  case SYS_TELL:
  {
    sys_tell(f);
    break;
  }
  case SYS_CLOSE:
  {
    sys_close(f);
    break;
  }
  default:
    break;
  }
}

// ************** SYSCALL FUNCTIONS **************
// ***********************************************

// SYS_HALT: terminates pintos by calling shutdown_power_off()
static void sys_halt()
{
  shutdown_power_off();
}

// SYS_EXIT: terminates current user program and returns status to the kernel.
// If a process's parent waits for it this is the status that will be returned.
// Status of 0 indicates success, and nonzero values indicate errors
static void sys_exit(struct intr_frame *f)
{
  check_stack_pointer(f, 1);
  // get arguments from stack
  int status = *((int *)((f->esp) + 4));
  thread_current()->child_elem->exit_status = status; // return status to kernel
  thread_exit();                                      // terminate current user prog
}

// SYS_EXEC:
static void sys_exec(struct intr_frame *f)
{
  check_stack_pointer(f, 1);
  // get arguments from stack
  const char *cmd_line = (const char *)*((unsigned *)((f->esp) + 4));
  // check for valid args
  if ((void *)(cmd_line) >= PHYS_BASE)
    thread_exit();
  else if (!pagedir_get_page(thread_current()->pagedir, cmd_line))
    thread_exit();
  // args are valid, execute the command
  tid_t tid = process_execute(cmd_line);
  // return tid of child
  if (tid == TID_ERROR)
    f->eax = (uint32_t)-1;
  else
    f->eax = (uint32_t)tid;
}

// SYS_WAIT:
static void sys_wait(struct intr_frame *f)
{
  check_stack_pointer(f, 1);
  // get arguments from stack
  tid_t tid = *((tid_t *)((f->esp) + 4));
  // return exit status of waited on child
  f->eax = process_wait(tid);
}

// SYS_CREATE:
static void sys_create(struct intr_frame *f)
{
  check_stack_pointer(f, 2);
  // get arguments from stack
  const char *file = (const char *)*((unsigned *)((f->esp) + 4));
  unsigned initial_size = *((size_t *)((f->esp) + 8));
  // check for valid args
  if ((void *)file >= PHYS_BASE)
    thread_exit();
  else if (!pagedir_get_page(thread_current()->pagedir, file))
    thread_exit();
  // lock filesys during access
  lock_acquire(&file_lock);
  // return success of remove
  f->eax = filesys_create(file, initial_size);
  lock_release(&file_lock);
}

// SYS_REMOVE:
static void sys_remove(struct intr_frame *f)
{
  check_stack_pointer(f, 1);
  // get arguments from stack
  const char *file = (const char *)*((unsigned *)((f->esp) + 4));
  // check for valid args
  if ((void *)file >= PHYS_BASE)
    thread_exit();
  else if (!pagedir_get_page(thread_current()->pagedir, file))
    thread_exit();
  // lock filesys during access
  lock_acquire(&file_lock);
  // return success of remove
  f->eax = filesys_remove(file);
  lock_release(&file_lock);
}

// SYS_OPEN:
static void sys_open(struct intr_frame *f)
{
  check_stack_pointer(f, 1);
  // get arguments from stack
  const char *file_name = (const char *)*((unsigned *)((f->esp) + 4));
  // check for valid args
  if ((void *)file_name >= PHYS_BASE)
    thread_exit();
  else if (!pagedir_get_page(thread_current()->pagedir, file_name))
    thread_exit();
  // set new fd based on the last used
  int fd = ++thread_current()->last_fd;
  // lock filesys during access
  lock_acquire(&file_lock);
  struct file *file = filesys_open(file_name);
  if (file)
  { // if file successfully opened, allocate space for a new file,
    // intialize it, and push it onto the fd_list
    struct fd_list_elem *new_file;
    new_file = malloc(sizeof(struct fd_list_elem));
    new_file->fd = fd;
    new_file->file = file;
    list_push_back(&thread_current()->fd_list, &new_file->file_elem);
    // return fd
    f->eax = fd;
  }
  else
  {
    // return error if file couldn't be opened
    f->eax = -1;
  }
  lock_release(&file_lock);
}

// SYS_FILESIZE:
static void sys_filesize(struct intr_frame *f)
{
  check_stack_pointer(f, 1);
  // get arguments from stack
  int fd = *((int *)((f->esp) + 4));
  // get file corresponding to fd
  struct fd_list_elem *current = find_file(fd);
  // lock filesys during access
  lock_acquire(&file_lock);
  if (current)
    f->eax = file_length(current->file); // return length of file
  else
    f->eax = 0; // return 0, file DNE
  lock_release(&file_lock);
}

// SYS_READ:
static void sys_read(struct intr_frame *f)
{
  check_stack_pointer(f, 3);
  // get arguments from stack
  int fd = *((int *)((f->esp) + 4));
  char *buffer = (void *)*((unsigned *)((f->esp) + 8));
  unsigned size = *((size_t *)((f->esp) + 12));
  // check for valid args
  if ((void *)buffer >= PHYS_BASE)
    thread_exit();
  else if (!pagedir_get_page(thread_current()->pagedir, buffer))
    thread_exit();
  // get file corresponding to fd
  struct fd_list_elem *current = find_file(fd);
  // lock filesys during access
  lock_acquire(&file_lock);
  if (current != NULL)
  {
    if (current->fd == 1)
    { // if fd == stdout
      lock_release(&file_lock);
      thread_exit();
    }
    else if (current->fd == 0)
    { // if fd == stdin
      char *input = (char *)buffer;
      for (unsigned i = 0; i < size; i++)
      {
        *input = input_getc();
        input++;
      }
    }
    else // fd corresponds to a regular file
      size = file_read(current->file, buffer, size);
    // return size of read
    f->eax = size;
  }
  else // return error
    f->eax = (uint32_t)-1;
  lock_release(&file_lock);
}

// SYS_WRITE:
static void sys_write(struct intr_frame *f)
{
  check_stack_pointer(f, 3);
  // get arguments from stack
  int fd = *((int *)((f->esp) + 4));
  char *buffer = (void *)*((unsigned *)((f->esp) + 8));
  unsigned size = *((size_t *)((f->esp) + 12));
  // check for valid args
  if ((void *)buffer >= PHYS_BASE)
    thread_exit();
  else if (!pagedir_get_page(thread_current()->pagedir, buffer))
    thread_exit();
  // get file corresponding to fd
  struct fd_list_elem *current = find_file(fd);
  // lock filesys during access
  lock_acquire(&file_lock);
  if (current != NULL)
  {
    if (current->fd == 0)
    { // if fd == stdin
      lock_release(&file_lock);
      thread_exit();
    }
    else if (current->fd == 1)
    { // if fd == stdout
      putbuf(buffer, size);
    }
    else // fd corresponds to a regular file
      size = file_write(current->file, buffer, size);
    // return size of write
    f->eax = size;
  }
  else // return error
    f->eax = 0;
  lock_release(&file_lock);
}

// SYS_SEEK:
static void sys_seek(struct intr_frame *f)
{
  check_stack_pointer(f, 2);
  // get arguments from stack
  int fd = *((int *)((f->esp) + 4));
  unsigned position = *((unsigned *)((f->esp) + 8));
  // get file corresponding to fd
  struct fd_list_elem *current = find_file(fd);
  // lock filesys during access
  lock_acquire(&file_lock);
  if (current)
    file_seek(current->file, position);
  lock_release(&file_lock);
}

// SYS_TELL:
static void sys_tell(struct intr_frame *f)
{
  check_stack_pointer(f, 1);
  // get arguments from stack
  int fd = *((int *)((f->esp) + 4));
  // get file corresponding to fd
  struct fd_list_elem *current = find_file(fd);
  // lock filesys during access
  lock_acquire(&file_lock);

  if (current)
  { // return position
    f->eax = file_tell(current->file);
  }
  else // file not found, return error
    f->eax = 0;
  lock_release(&file_lock);
}

// SYS_CLOSE:
static void sys_close(struct intr_frame *f)
{
  check_stack_pointer(f, 1);
  // get arguments from stack
  int fd = *((int *)((f->esp) + 4));
  // get file corresponding to fd
  struct fd_list_elem *current = find_file(fd);
  // lock filesys during access
  lock_acquire(&file_lock);
  if (current != NULL && current->fd > 1)
  {
    file_close(current->file);
    list_remove(&current->file_elem);
    free(current);
  }
  lock_release(&file_lock);
}

// **** Helper Functions ****

// Returns the file entry corresponding to the provided fd
static struct fd_list_elem *find_file(int fd)
{
  struct list_elem *e;
  struct fd_list_elem *current;

  for (e = list_begin(&thread_current()->fd_list);
       e != list_end(&thread_current()->fd_list); e = list_next(e))
  {
    current = list_entry(e, struct fd_list_elem, file_elem);
    if (current->fd == fd)
      return current;
  }

  return NULL;
}

void check_stack_pointer(struct intr_frame *f, int num_args)
{
  int offset = 4 * num_args;
  if (((f->esp) + offset) >= PHYS_BASE)
    thread_exit();
  else if (!pagedir_get_page(thread_current()->pagedir, f->esp + offset))
    thread_exit();
}