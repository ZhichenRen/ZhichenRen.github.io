---
layout: post
title: "CSAPP:Attack Lab"
date: 2021-07-28
author: ZhichenRen
categories: CSAPP
tags: CSAPP AttackLab
description: 前几天看完了CSAPP第三章，做了人生当中第一个像样的lab，纪念一下
---
# Attack Lab
## 简介
这个lab是利用缓冲区溢出来对程序进行攻击，让程序偏离正常运行，转而运行攻击者所希望的代码。

lab提供可执行程序ctarget与rtarget，前者为代码注入攻击(Code Injection Attack)所使用的可执行程序，后者为ROP(Return-Oriented Programming)所使用的可执行程序，区别仅在于rtarget开启了栈随机化并将栈区设置为不可执行。

可执行文件中包含如下test函数：
```c++
void test(){
    int val;
    val = getbuf();
    printf("No exploit. Getbuf returned 0x%x\n", val);
}
```
该函数将调用getbuf函数：
```c++
unsigned getbuf(){
    char buf[BUFFER_SIZE];
    Gets(buf);
    return 1;
}
```
这里的Gets()函数类似于库函数gets()，没有考虑输入的大小，因此可能出现缓冲区溢出的问题，我们可以利用这一漏洞改变程序的行为。

可执行文件中包含如下函数，我们需要利用缓冲区溢出漏洞依次执行这些函数：
```c++
//touch1函数没有输入参数，直接调用即可。
void touch1(){
    vlevel = 1; /* Part of validation protocol */
    printf("Touch1!: You called touch1()\n");
    validate(1);
    exit(0);
}



//touch2函数需要一个参数val，我们在进行攻击时需要设置参数再进行调用。
void touch2(unsigned val){
    vlevel = 2; /* Part of validation protocol */
    if (val == cookie) {
        printf("Touch2!: You called touch2(0x%.8x)\n", val);
        validate(2);
    }
    else {
        printf("Misfire: You called touch2(0x%.8x)\n", val);
        fail(2);
    }
    exit(0);
}


//touch3函数需要一个指针参数，我们应当将Cookie字符串存于某一个位置，并将其地址传入。
void touch3(char *sval){
    vlevel = 3; /* Part of validation protocol */
    if (hexmatch(cookie, sval)) {
        printf("Touch3!: You called touch3(\"%s\")\n", sval);
        validate(3);
    }
    else {
        printf("Misfire: You called touch3(\"%s\")\n", sval);
        fail(3);
    }
    exit(0);
}

//touch3函数将调用此函数用于Cookie字符串比较，此函数中的cbuf数组写入可能会破坏存于栈中的字符串
int hexmatch(unsigned val, char *sval)
{
    char cbuf[110];
    /* Make position of check string unpredictable */
    char *s = cbuf + random() % 100;
    sprintf(s, "%.8x", val);
    return strncmp(sval, s, 9) == 0;
}
```

## Code Injection Attack
### Level 1
最简单的攻击，只需要改变getbuf返回的地址即可。使用gdb进入getbuf函数，发现其为buf分配了40Byte的栈空间，而超过40Byte的输入字符串则会覆盖其返回地址，因此我们只需在攻击字符串的前40Byte填上任意字符，在接下来的8Byte中填写touch1函数的返回值即可。

### Level 2
Level2需要跳转至touch2函数，这同样是通过修改存放在栈中的返回值实现的。区别在于touch2需要一个unsigned参数，也就是Cookie.txt中的16进制数，我们需要在跳转至touch2之间将其存放至%rdi（存放第一个参数的寄存器）中。
具体思路如下：
1. 修改栈顶返回值，跳转至栈中某一块被我们修改过的内存，这块内存中将存放需要执行的指令
2. 从跳转处开始执行指令，将Cookie存放至%rdi中
3. 将touch2函数的地址压栈，并通过ret跳转至touch2函数

所用到的汇编指令位于assembly/level2.s中，攻击字符串存放于solution/level2.txt中
### Level 3
Level3与Level2的主要区别如下：
- Level2中的touch2的参数为一个unsigned，攻击代码仅需传入立即数即可，而Level3中的touch3函数的参数为一个字符串指针，这意味着我们的攻击代码需要将Cookie转化为ASCII字符串并存放于内存中的指定位置
- Level3中的touch3函数将调用hexmatch函数，该函数将创建一个cbuf数组并在其随机位置写入内容，这有可能会覆盖我们存放在栈空间中的字符串，因此我们应当在栈的更高位存放字符串（我存放于test函数的缓冲区中）

具体思路如下：
1. 修改栈顶返回值，使ret跳转至注入的攻击代码，同时将字符串存放于test对应的栈帧中
2. 将存放字符串的地址放入%rdi中
3. 将touch3的地址压栈，使用ret跳转

## Return-Oriented Programming
rtarget可执行文件增加了栈随机化，且栈不可执行，因此代码注入攻击很难起到效果，使用ROP进行攻击。首先介绍一下gadget的概念，gadget是一小条指令序列，并且以ret(c3)结尾，例如：
```x86asm
0000000000400f15 <setval_210>:
400f15: c7 07 d4 48 89 c7 movl $0xc78948d4,(%rdi)
400f1b: c3 retq
```
这条指令虽然看上去没有什么作用，但是如果我们从0x400f18处开始执行，它就是48 89 c7，也就是movq %rax,%rdi。可以变得为我们所用。另外，紧随其后的ret语句可以让我们跳转至另一个gadget继续执行。因此，所谓的ROP攻击就是利用一连串的gadget来执行一些我们所需要的指令。由于代码区在内存中的位置是固定的且是可执行的，这就解决了上文提到的栈随机化与栈不可执行的问题。

### Level 2
了解了gadget的原理，这个attack也不是很困难。我们需要做的事情如下：
1. 将Cookie存放于内存中，通过pop指令来读取
2. 将读取到的Cookie存入%rdi中
3. 调用touch2函数

```x86asm
popq %rsp, %rax 
ret
movq %rax,%rdi 
ret
```
共需要两个gadget即可完成，攻击字符串存放于solutions/rop-2.txt中，gadget的信息存放于gadgets.txt中。
### Level 3
这个攻击是此lab中最复杂的一个，需要用到8个gadget，大致思路类似phase3与phase4的结合，用ROP的思想来完成我们在phase3所完成的事情。

大致思路如下：
1. 首先，我们需要把字符串存放于test的栈帧中
2. 然后我们需要获取字符串的起始地址，由于开启了栈随机化，我们无法直接给出这个地址，需要使用rsp与偏移量的方式来获取
3. 最后将字符串起始地址存放于%rdi中，调用touch3即可

我们希望执行的汇编代码如下：
```x86asm
popq %rax
ret
movq %rsp,%rdi
ret
lea (%rdi,%rax,1),%rdi
ret
```
其中每一个ret都将调用下一个gadget来执行对应的汇编代码。但是很不巧的是，我们能够利用的gadget库中没有能够帮助我们产生后两条指令的gadget，因此我们需要稍微绕一点路，将我们所想要执行的动作转化为gadget所支持的指令，如下：
```x86asm
popq %rax
ret
movl %eax,%edx
ret
movl %edx,%ecx
ret
movl %ecx,%esi
ret
movq %rsp,%rax
ret
movq %rax,%rdi
ret
lea (%rdi,%rsi,1) %rax
ret
movq %rax,%rdi
ret
```
最后根据指令的设计来计算movq %rsp,%rax指令与字符串起始位置的偏移量，本解法中为32，并将其写入栈中。
攻击字符串存放于solutions/rop-3.txt中。