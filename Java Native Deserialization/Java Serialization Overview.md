
`Java`安全的相关的知识学了很多。虽然零零散散的记录了一些，但不成体系，不利于回顾和后续学习。这篇文章主要是汇总`Java`反序列化漏洞相关的知识面，内容大多来自网络和个人所学，文章以整理陈述为主，外加一些个人理解。
## 反序列化的概念
序列化与反序列化（`marshal/unmarshal`）是一种存储和转化数据（将数据变为内存中对象或变量，反之亦然）的方式，例如`json`、`xml`等文件格式，它是一种通用的概念。当然`java`中的序列化与反序列化也有自己的[标准]([Java Object Serialization Specification: Contents (oracle.com)](https://docs.oracle.com/javase/8/docs/platform/serialization/spec/serialTOC.html))。
序列化的目的主要是为了便于将程序运行时的数据以某种约定好的形式在网络中传输，从而实现一些功能，例如`RPC`（`Remote Procedure Call`）。本文主要涉及的`Java`中的序列化以及它的相关使用场景和漏洞等。
## Java序列化
`Java`标准中定义了与序列化相关的接口，`ObjectOutput`、`ObjectInput`、`Serializable`、`Externalizable`。前两个接口中定义了读写序列化数据的方法签名，它们中`java.io`库中已有标准实现，分别是`ObjectOutputStream`和`ObjectInputStream`。如果一个类希望它所对应的对象能够被序列化则需要实现`Serializable`、`Externalizable`中的一个。现在不必纠结这些接口的用法，后面会逐步介绍
```java
public interface Serializable {
	// 皆为可选
	static final long serialVersionUID = 42L;
	private void writeObject(ObjectOutputStream out)
	   throws IOException;
	private void readObject(ObjectInputStream in)
	   throws IOException, ClassNotFoundException;
	private void readObjectNoData()
	   throws ObjectStreamException;
	Object writeReplace() throws ObjectStreamException;
	Object readResolve() throws ObjectStreamException;
}

public interface Externalizable extends Serializable {
	// 必选
    public void writeExternal(ObjectOutput out)
        throws IOException;

    public void readExternal(ObjectInput in)
        throws IOException, java.lang.ClassNotFoundException;
}
```
### 快速开始
你可以通过调用`ObjectOutputStream#writeObject`方法写入对象（序列化）或是调用`ObjectInputStream#readObject`方法读取对象（反序列化）
下面来看具体示例，通过`writeObject`方法将序列化后的数据写入文件`ser.dat`中。
```java
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.dat"));
oos.writeObject(new SerData());
```
不过如果希望上面的代码块成功执行，`SerData`需要实现`Serializable`接口。
```java
class SerData implement Serializable {
	...
}
```
当读取序列化后的对象时，调用`readObject`方法即可
```java
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ser.dat"));  
Object object = ois.readObject();
```
这是最基础的用法，理解起来并不困难，对象变成数据，数据再度恢复为一个对象。在序列化化时，`ObjectOutputStream`会将`SerData`类对象的各个成员和类名等存入数据流中。那如果一个对象被重复写入会发生什么呢？请看如下代码
```java
SerData serData = new SerData();  
oos.writeObject(serData);  
oos.writeObject(serData);
```
由于序列化无法记录或恢复对象在内存中的地址，它会为对象分配一个`serial number`作为一个标识，那么在第二次写入时仅写入对第一次写入的引用（`serial number`）。
![figure_1.1.svg](https://cdn.nlark.com/yuque/0/2022/svg/22838900/1658929415110-3cf48071-32f2-4493-a6c9-12060468087b.svg#clientId=u56327093-60da-4&crop=0&crop=0&crop=1&crop=1&from=drop&height=371&id=ud2575407&margin=%5Bobject%20Object%5D&name=figure_1.1.svg&originHeight=765&originWidth=1360&originalType=binary&ratio=1&rotation=0&showTitle=false&size=88429&status=done&style=shadow&taskId=u5041f473-620d-4f67-91a5-909948b727d&title=&width=659)

这看上去多少有些抽象，在后续讲解`Java`序列化格式时会再次回顾它。那么`writeObject`会将对象成员都写入文件吗？并不都是，它会略过`static`和`transient`成员，`readObject`也是类似的。

- `void writeObject(Object obj)`：向数据流中写入对象类签名以及`static`和`transient`之外的成员（包括父类）
- `Object readObject()`：从数据流中读取对象类签名，创建并恢复其`static`和`transient`之外的成员值。
### Serializable接口
每个希望支持序列化操作的类，都需要实现该接口，并且它支持通过定义`readObject/writeObject`方法来修改默认的序列化行为。为了保证序列化的一致性，`readObject/writeObject`的逻辑顺序也需要是一致的。这种定义`readObject/writeObject`方法的行为在反序列化漏洞的利用中尤为常见，它们通常是反序列化利用的起点。
```java
public class SerData implements Serializable {
    private static final long serialVersionUID = 2L;
    
    private void writeObject(ObjectOutputStream out)
        throws IOException {
        out.defaultWriteObject();
        // user define operate
    }
    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // user define operate
    }
}
```
除了`readObject/writeObject`外，与`Serializable`接口相关的方法还有`readResolve`、`writeReplace`，`readObjectNoData`。在`Serializable`接口的注释中写明了它们的作用，但可能并不容易理解。下面依次来看它们的作用
#### writeReplace
通常来讲，并不会使用到该方法。如果该方法被定义，那么序列化时会调用它（而不是`writeObject`），并将它返回到对象写入序列化流中。
```java
public class SerData implements Serializable {
    private static final long serialVersionUID = 2L;

    private void writeObject(ObjectOutputStream out)
            throws IOException {
        System.out.println("Call writeObject");
        out.defaultWriteObject();
    }

    private Object writeReplace() throws ObjectStreamException {
        System.out.println("Call writeReplace");
        return new String("writeReplace");
    }
}
```
此时尝试序列化一个`SerData`对象，它的输出为`Call writeReplace`，并且写入的内容是一个`String`对象。
```bash
➜  hexdump -C ser.dat
00000000  ac ed 00 05 74 00 0c 77  72 69 74 65 52 65 70 6c  |��..t..writeRepl|
00000010  61 63 65                                          |ace|
00000013
```
#### readResolve
它和`writeReplace`类似，它会被先调用（如果同时定义了`readObject`）。可以借助它在读取时返回你需要的对象，它会替换原本应被读出对对象（默认情况`in.defaultReadObject()`