foreach($task in get-scheduledtask){
    if((get-scheduledtaskinfo $task).NextRunTime){
        (Get-ScheduledTaskInfo $task).TaskName
        (Get-ScheduledTask).NextRunTime
        write-host ""
    }
}
