# NtCreateUserProcess

## init 
参考@captmeelo分享过`NtCreateUserProcess`来启动程序,实现`NtCreateUserProcess`来结合Blockdll和ppid欺骗

这里有一个缺陷是会`CREATE_NEW_CONSOLE`,尝试过很多方式都无效,使用`ProcessParameters->ShowWindowFlags = SW_HIDE`也没有效果，想到比较笨的办法是去找窗口名称，然后调用`ShowWindow`函数,但这也太笨了...

欢迎有想法的师傅一起交流呀~

## usage
封装成`SelfNtCreateUserProcess`函数:
```
NTSTATUS SelfNtCreateUserProcess(
	wchar_t* path,
	wchar_t* parameter,
	DWORD ppid,
	BOOL blockdll
)
```
不需要ppid欺骗直接填0,没有参数直接为空`""`