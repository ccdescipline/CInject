# Cinject

Cinject is a project that executes dll injection in the Windows kernel. It is characterized by no modules and no threads. It uses remote stretching pe to achieve no modules. It uses APC or SupendThread to replace Rip registers to hijack threads to achieve no threads. The running environment was tested in 1909. If you want to run in other versions, you need to modify and find the function signatures of `KeSuspendThread` and `KeResumeThread`. I will tell you how to modify the offset of `OFFSET_KTRAP_FRAME` below. The injected dll also requires attributes ->code generation ->runtime multi-threaded MT. In short, other dll modules in the import table of the dll must also exist in the target process!



## Objectives

Temporarily test that the Apex Legends protected by EAC can be injected in 1909 (Os version 18363)



## How to find KeSuspendThread and KeResumeThread?

You need to open `windbg` in the target system as an administrator to open `Kernel Debug`, enter `u KeSuspendThread` to view the KeSuspendThread function address and disassembly, and record the characteristic code. The same is true for KeResumeThread, and finally in EipInject Cpp Modify the signature in the `FindKeSuspendThread` and `FindKeResumeThread` functions.



## How to modify OFFSET_ KTRAP_ FRAME？

It is in EipInject H 'is the same as above. You also need the windbg administrator to start and enable kernel debugging, and type `dt_ KTHREAD` View `_KTRAP_FRAME` The offset can be modified



## Switch APC and EIP modes

In the `injectDll` function, you can use `APCExecuteFunction` or `EipExceptionFunction` to switch between different execution methods

# Cinject
Cinject 是在windows内核执行dll注入的一个项目，特点是无模块和无线程，使用远程拉伸pe实现无模块，使用APC 或 SupendThread 替换Rip寄存器劫持线程实现无线程，运行环境在1909得到测试，如想在其他版本运行，需要修改寻找  `KeSuspendThread` 和 `KeResumeThread` 函数特征码和 `OFFSET_KTRAP_FRAME` 的偏移，我会在下文告诉大家如何修改。注入的dll也有要求，属性->代码生成->运行库 多线程MT。简单来说就是该dll的导入表里的其他dll模块在目标进程里也必须存在！

## 目标
暂时测试可以注入受EAC 保护的 Apex legends 在 1909（Os version 18363）

## 怎样寻找 KeSuspendThread 和 KeResumeThread？
您需要在目标系统中以管理员方式打开 `windbg` 开启 `Kernel Debug` 输入 ` u KeSuspendThread `即可查看 KeSuspendThread 函数地址和反汇编，记录下特征码即可，KeResumeThread 也是如此 `u KeResumeThread ` ,最后在EipInject.cpp修改`FindKeSuspendThread` 和 `FindKeResumeThread`函数里的特征码即可。

## 怎样修改 OFFSET_KTRAP_FRAME？
它在` EipInject.h `中 同上，也需要windbg管理员启动并开启内核调试，键入 `dt _KTHREAD` 查看 `_KTRAP_FRAME`的偏移，修改即可

## 切换APC 和 EIP 方式
在` injectDll `函数中，你可以使用 `APCExecuteFunction` 或`EipExcuteFuntion` 切换不同的执行方式
