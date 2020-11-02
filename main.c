#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parse.h"
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>  
#include <fcntl.h>      
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fnmatch.h>
#include <glob.h>
#include<limits.h>

pid_t childPid;
pid_t child_Pid;
int status;
int pipefd[2];
int pInd = 0;
bool ifPipeExists;
int commandCounter = 0;


static void execCd(Cmd c){
  char *tFdPath = (char *)malloc(1024);
  strcpy(tFdPath, getenv("HOME"));
  if(c->args[1] == NULL  || !strcmp(c->args[1],"~")){
    c->args[1] = malloc(strlen(tFdPath));
    strcpy(c->args[1],tFdPath);
  }

  if (chdir(c->args[1]) == -1) {
    char tFdCwd[1024];
    if(getcwd(tFdCwd, 1024)!=NULL){
      printf("Cd Error\n");
    }
  }
}

static void execEcho(Cmd c){
  
  // For environment variables
  if (c->args[1][0] == '$'){
      char *tFdEnv = strtok(c->args[1],"$");
      char *env = getenv(tFdEnv);
      if (env != NULL)
        printf("%s\n", env);
      else
        printf("\n");
  }
  // For text print in new line
  else {
    int i=1;
    while(c->args[i] != NULL){
      printf("%s ",c->args[i]);
      i++;
    }
    printf("\n");
  }
}
static void execLogout(Cmd c){
  exit(0);
}
static void execNice(Cmd c){

  int shellOrCmd = 0; // 0 for shell, 1 for command
  int priority = 0;
  int cmdIndex = 0;

  if (c->args[1] != NULL){
    if (c->args[1] != NULL && c->args[2] != NULL){
      priority = atoi(c->args[1]);
      cmdIndex = 2;
      shellOrCmd = 1;

    }
    if (c->args[1] != NULL && c->args[2] == NULL){
      priority = atoi(c->args[1]);
      if (priority == 0){
        if(strlen(c->args[1]) > 3){
          priority = 4;
          cmdIndex = 1;
          shellOrCmd = 1;
        } else {
          shellOrCmd = 0;
        }
      } else {
        shellOrCmd = 0;
      }
    }
  }
  else {
    shellOrCmd = 0;
    priority = 4;
  }
  // Modern linux system Nice priority range
  //http://man7.org/linux/man-pages/man7/sched.7.html
  if (priority < -20){
    priority = -20;
  }
  else if (priority > 19) {
    priority = 19;
  }

  // printf("%d %d %d\n", shellOrCmd, priority , cmdIndex);
  child_Pid = fork();
  if(child_Pid == 0){
    int which = PRIO_PROCESS;
    getpriority(which, child_Pid);
    setpriority(which, child_Pid, priority);
    if(execvp(c->args[cmdIndex], c->args+cmdIndex) == -1){
        fprintf(stderr,"%s: command not found\n",c->args[cmdIndex]);       
        exit(0);  
    }
  } else {   
    //waitpid(child_Pid, &status,0);
    waitpid(child_Pid, NULL, 0);
  }
}

static void execPwd(Cmd c){
  char tFdCwd[1024];
  getcwd(tFdCwd, sizeof(tFdCwd));
  printf("%s\n", tFdCwd);
}

static void execSetenv(Cmd c){
  if (c->args[1] != NULL && c->args[2] != NULL && c->args[3] != NULL ){
    if(setenv(c->args[1],c->args[2],atoi(c->args[3])) == -1){
      fprintf(stderr, "SetEnv Error\n");
      return; 
    }
  }
  if (c->args[1] != NULL && c->args[2] != NULL && c->args[3] == NULL ){
    if(setenv(c->args[1],c->args[2],1) == -1){
      fprintf(stderr, "SetEnv Error\n");
      return; 
    } 
  }
}

static void execUnsetenv(Cmd c){
  if (c->args[1] != NULL){
    if(unsetenv(c->args[1]) == -1){
      fprintf(stderr, "UnSetEnv Error\n");
      return; 
    }
  }
}

static void execWhere(Cmd c){

  char *path = getenv("PATH");
  char tFd_cmd[1024] = "";
  char *token = strtok(path,":");

  if (c->args[1] != NULL){
    while(token != NULL)
    {
      strcpy(tFd_cmd,token);
      strcat(tFd_cmd,"/");
      strcat(tFd_cmd,c->args[1]);
      if(access(tFd_cmd,F_OK) == 0) 
      {
          printf("%s\n",tFd_cmd);
      }
      token = strtok(NULL,":");
    }
  }
}

void prCmdToken(Token t){
  if (t == Terror)
    printf("Token: Terror\n"); 
  else if (t == Tamp)
    printf("Token: Tamp\n"); 
  else if (t == Tpipe)
    printf("Token: Tpipe\n"); 
  else if (t == Tin)
    printf("Token: Tin\n"); 
  else if (t == Tout)
    printf("Token: Tout\n"); 
  else if (t == Tapp)
    printf("Token: Tapp\n"); 
  else if (t == TpipeErr)
    printf("Token: TpipeErr\n"); 
  else if (t == ToutErr)
    printf("Token: ToutErr\n"); 
  else if (t == TappErr)
    printf("Token: TappErr\n"); 
  else if (t == Tend)
    printf("Token: Tend\n"); 
  else
    printf("Token: NONE\n"); 
}

pid_t child;
int checkBuiltInCmds(Cmd c)
{
  if(strcmp(c->args[0],"cd") == 0)
    return 0;
  else if(strcmp(c->args[0],"echo") == 0)
    return 1;
  else if(strcmp(c->args[0],"logout") == 0 || strcmp(c->args[0],"exit") == 0)
    return 2;
  else if(strcmp(c->args[0],"nice") == 0)
    return 3;
  else if(strcmp(c->args[0],"pwd") == 0)
    return 4;
  else if(strcmp(c->args[0],"setenv") == 0) 
    return 5;
  else if(strcmp(c->args[0],"unsetenv") == 0)
    return 6;
  else if(strcmp(c->args[0],"where") == 0)
    return 7;
  else
    return -1;

}

static void execBuiltInCmds(Cmd c)
{
  if(strcmp(c->args[0],"cd") == 0)
    execCd(c);
  else if(strcmp(c->args[0],"echo") == 0)
    execEcho(c);
  else if(strcmp(c->args[0],"logout") == 0 || strcmp(c->args[0],"exit") == 0)
    execLogout(c);  
  else if(strcmp(c->args[0],"nice") == 0)
    execNice(c);
  else if(strcmp(c->args[0],"pwd") == 0)
    execPwd(c);
  else if(strcmp(c->args[0],"setenv") == 0) 
    execSetenv(c);
  else if(strcmp(c->args[0],"unsetenv") == 0)
    execUnsetenv(c);
  else if(strcmp(c->args[0],"where") == 0)
    execWhere(c);   
}


void checkPermissions(Cmd c) {
  int tFd;
  
  // Checks for input token
  if(c->in == Tin)
  {
    if((tFd = open(c->infile,O_RDONLY)) != -1)
    {
      if(dup2(tFd,0) == -1)
      {
        fprintf(stderr, "checkPermissions: Tin Input dup2 failed\n");
        return;
      }
      close(tFd);
    }
    else {
      fprintf(stderr, "%s: Permission denied\n", c->infile);
      exit(0);   
    }
  }

  // Checks for Output tokens
  if(c->out == Tout)
  {
    if((tFd = open(c->outfile,O_CREAT|O_WRONLY|O_TRUNC,0660)) != -1)
    { 
      if(dup2(tFd,1) == -1)
      {
        fprintf(stderr, "checkPermissions: Tout Output dup2 failed\n");
        return;
      }
      close(tFd);
    }
    else {
      fprintf(stderr, "%s: Permission denied\n", c->outfile);
      exit(0);
    }
  }

  else if(c->out == ToutErr)
  {
    if((tFd = open(c->outfile,O_CREAT|O_WRONLY|O_TRUNC,0660)) != -1)
    { 
      if(dup2(tFd,1) == -1)
      {
        fprintf(stderr, "checkPermissions: ToutErr Output dup2 failed\n");
        return;
      }
      if(dup2(tFd,2) == -1)
      {
        fprintf(stderr, "checkPermissions: ToutErr Error dup2 failed\n");
        return;
      }
      close(tFd);
    }
    else {
      fprintf(stderr, "%s: Permission denied\n", c->outfile);
      exit(0);
    }
  }
  
  else if(c->out == Tapp)
  { 
    if((tFd = open(c->outfile,O_CREAT|O_WRONLY|O_APPEND,0660)) != -1)
    { 
      if(dup2(tFd,1) == -1)
      {
        fprintf(stderr, "checkPermissions: Tapp Error dup2 failed\n");
        return;
      }
      close(tFd);
    }
    else {
      fprintf(stderr, "%s: Permission denied\n", c->outfile);
      exit(0);
    }
  }

  else if(c->out == TappErr)
  {
    if((tFd = open(c->outfile,O_CREAT|O_WRONLY|O_APPEND,0660)) != -1)
    { 
      if(dup2(tFd,1) == -1)
      {
        fprintf(stderr, "checkPermissions: TappErr Output dup2 failed\n");
        return;
      }
      if(dup2(tFd,2) == -1)
      {
        fprintf(stderr, "checkPermissions: TappErr Error dup2 failed\n");
        return;
      }
      close(tFd);
    }   
    else {
      fprintf(stderr, "%s: Permission denied\n", c->outfile);
      exit(0);
    }
  }
} 

void execShellPipeline(Cmd c) {

  int t_stdin;
  int t_stdout;
  int t_stderr;

  fflush(stdin);
  fflush(stdout);
  // Saving steaming varaiables for buildin command to execte in subshell
  t_stdin = dup(0);
  t_stdout = dup(1);
  t_stderr = dup(2);
  if (t_stdin == -1 || t_stdout == -1 || t_stderr == -1){
    fprintf(stderr, "stream dup error\n");
    return;
  }

  // If pipe exists in input command, create pipe 
  bool lastPipe = false;
  if(c->out == Tpipe)
  {
    int ret = pipe(pipefd+pInd); 
    if (ret == -1) {
      fprintf(stderr, "Pipe Error\n");
      return;
    } else {     
      ifPipeExists = true; 
    }
    // Increment for next pipe
    pInd = pInd + 2;
    
  }
  if (ifPipeExists && (commandCounter > 0))
    lastPipe = true;

  if (checkBuiltInCmds(c) != -1){
  
    if(c->out == Tpipe){
      if (dup2(pipefd[pInd-1],1) == -1) exit(0);    
    } else if (c->out == TpipeErr) {
      if (dup2(pipefd[pInd-1],1) == -1) exit(0);        
      if (dup2(pipefd[pInd-1],2) == -1) exit(0);      
    }

    if(lastPipe)
    {     
      if(c->out == Tpipe || c->out == TpipeErr){
        if (dup2(pipefd[pInd-4],0) == -1) exit(0);      
      } else {
        if (dup2(pipefd[pInd-2],0) == -1) exit(0);    
      } 
    }

    execBuiltInCmds(c);

    int r1, r2, r3;
    
    r1 = dup2(t_stdin,0);
    r2 = dup2(t_stdout,1);
    r3 = dup2(t_stderr,2);
    if (r1 == -1 || r2 == -1 || r3 == -1){
      fprintf(stderr, "Stream dup2 error\n");
      return;
    }
    close(t_stdin);
    close(t_stdout);
    close(t_stderr);  

  } 
  else {

    childPid = fork();
    if(childPid == 0){
      
      if(c->out == Tpipe){
        if (dup2(pipefd[pInd-1],1) == -1) exit(0);    
      } else if (c->out == TpipeErr) {
        if (dup2(pipefd[pInd-1],1) == -1) exit(0);        
        if (dup2(pipefd[pInd-1],2) == -1) exit(0);      
      }
      checkPermissions(c);

      if(lastPipe)
      {     
        if(c->out == Tpipe || c->out == TpipeErr){
          if (dup2(pipefd[pInd-4],0) == -1) exit(0);      
        } else {
          if (dup2(pipefd[pInd-2],0) == -1) exit(0);    
        } 
      }

      if(execvp(c->args[0], c->args) == -1){
        fprintf(stderr,"%s: invalid command\n",c->args[0]);       
        // printf("%s\n",c->args[0]);
        exit(0);  
      }
      exit(0);        
    }
    else{

      waitpid(childPid,&status,0);

      commandCounter++;
      if(ifPipeExists){
        close(pipefd[pInd-1]);
        if(pInd-4 >= 0){
          close(pipefd[pInd-4]);
        } 
      }
    }
  }
}

static void prCmd(Cmd c)
{
  int i;

  if (c) {
    printf("%s%s ", c->exec == Tamp ? "BG " : "", c->args[0]);
    if ( c->in == Tin )
      printf("<(%s) ", c->infile);
    if ( c->out != Tnil )
      switch ( c->out ) {
        case Tout:
        printf(">(%s) ", c->outfile);
        break;
        case Tapp:
        printf(">>(%s) ", c->outfile);
        break;
        case ToutErr:
        printf(">&(%s) ", c->outfile);
        break;
        case TappErr:
        printf(">>&(%s) ", c->outfile);
        break;
        case Tpipe:
        printf("| ");
        break;
        case TpipeErr:
        printf("|& ");
        break;
        default:
        fprintf(stderr, "Shouldn't get here\n");
        exit(-1);
      }

      if ( c->nargs > 1 ) {
        printf("[");
        for ( i = 1; c->args[i] != NULL; i++ )
         printf("%d:%s,", i, c->args[i]);
       printf("\b]");
     }
     putchar('\n');
    // this driver understands one command
     if ( !strcmp(c->args[0], "end") )
      exit(0);
  }
}

static void prPipe(Pipe p)
{
  Cmd c;
  commandCounter = 0;
  if ( p == NULL )
    return;
  for ( c = p->head; c != NULL; c = c->next ) {
    execShellPipeline(c);
  }
  ifPipeExists = false;
  pInd = 0;
  prPipe(p->next);
}

//Signal handling for keyboard interrupts
void signalHandling()
{
  signal (SIGQUIT, SIG_IGN);
  signal (SIGHUP, SIG_IGN);
  signal (SIGTSTP, SIG_IGN);
  signal (SIGINT, SIG_IGN);
}
//ushrc execution handling
void ushrcCheck()
{
  int t_stdin, rcFh;
  char *rcPath = (char *)malloc(1024);
  strcpy(rcPath, getenv("HOME"));
  rcPath = strcat(rcPath, "/.ushrc");
  rcFh = open(rcPath,O_RDONLY);
  if(rcFh != -1)
  {
    t_stdin = dup(0);
    if(t_stdin == -1)
      return;
    
    if(dup2(rcFh,0)==-1)
      return;
  } else{
    // printf(".ushrc not readable\n");
    return;
  }
  
  Pipe p;
  int ret = 0;
  char *host = (char *)malloc(1024);
  gethostname(host,1024); 

  while (1) {
    fflush(stdin);
    fflush(stdout);
    if(isatty(0)){
       printf("%s%% ", host);
    }
    p = parse();

    if(p == NULL)  continue;
    ret = strcmp(p->head->args[0], "end");
    if(p!=NULL && ret)prPipe(p);
    else if(isatty(0) && !ret)exit(0);
    else if(!isatty(0) && !ret)break;
    // prPipe(p);
    freePipe(p);
  }
  dup2(t_stdin,0);
  close(rcFh);
  close(t_stdin);
}

int main(int argc, char *argv[])
{
  Pipe p;
  int ret = 0;
  char *host = (char *)malloc(1024);
  gethostname(host,1024); 
  signalHandling();
  ushrcCheck();

  while (1) {
    fflush(stdin);
    fflush(stdout);
    if(isatty(0)){
       printf("%s%% ", host);
    }
    p = parse();

    if(p == NULL)  continue;
    ret = strcmp(p->head->args[0], "end");
    if(p!=NULL && ret)prPipe(p);
    else if(isatty(0) && !ret)exit(0);
    else if(!isatty(0) && !ret)break;
    // prPipe(p);
    freePipe(p);
  }
}

