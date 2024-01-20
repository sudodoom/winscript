foreach($task in get-scheduledtask){
    if((get-scheduledtaskinfo $task).NextRunTime){
        (Get-ScheculedTaskInfo $task).TaskName
        (Get-ScheduledTask).NextRunTime
        write-host ""
    }
}