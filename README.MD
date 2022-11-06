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