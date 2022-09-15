
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
它和`writeReplace`类似，它会被先调用（如果同时定义了`readObject`）。可以借助它在读取时返回你需要的对象，它会替换原本应被读出对对象（默认情况`in.defaultReadObject()`）。
```java
public class SerData implements Serializable {
    private static final long serialVersionUID = 2L;

    private void writeObject(ObjectOutputStream out)
            throws IOException {
        System.out.println("Call writeObject");
        out.defaultWriteObject();
    }

    private Object readResolve() throws ObjectStreamException {
        System.out.println("Call readResolve");
        return new String("string");
    }
}
```
### Externalizable接口
这个接口是为了让开发人员完全自定义序列化逻辑而给出的，它的优先级高于`Serializable`接口，通过它可以按自己的逻辑规则定义对象序列化后的格式。具体不在这里展开，它在反序列化漏洞中出现的并不多。
### 对象序列化格式
了解了序列化接口的使用，再来看对象序列化后的格式可以加深理解。以前面章节的示例内容作展示，查看其输出文件中的内容，如下：
```bash
➜ hexdump -C ser.dat
00000000  ac ed 00 05 73 72 00 15  63 6f 6d 2e 74 72 67 61  |��..sr..com.trga|
00000010  6e 64 61 2e 61 2e 53 65  72 44 61 74 61 00 00 00  |nda.a.SerData...|
00000020  00 00 00 00 02 02 00 00  78 70 71 00 7e 00 01     |........xpq.~..|
0000002f
```
它存储这一个类型为`com.trganda.a.SerData`的对象的数据，内容较为简单。下面先介绍它的格式，再给出完整的`Java`序列化标准中定义的格式内容。
可以借助[SerializationDumper](https://github.com/NickstaDB/SerializationDumper)工具来解析序列化文件的内容，运行
```java
java -jar SerializationDumper-v1.13.jar -r ser.dat
```
输出如下
```java
STREAM_MAGIC - 0xac ed
STREAM_VERSION - 0x00 05
Contents
  TC_OBJECT - 0x73
    TC_CLASSDESC - 0x72
      className
        Length - 21 - 0x00 15
        Value - com.trganda.a.SerData - 0x636f6d2e747267616e64612e612e53657244617461
      serialVersionUID - 0x80 fe ea 9a aa da ac 40
      newHandle 0x00 7e 00 00
      classDescFlags - 0x02 - SC_SERIALIZABLE
      fieldCount - 0 - 0x00 00
      classAnnotations
        TC_ENDBLOCKDATA - 0x78
      superClassDesc
        TC_NULL - 0x70
    newHandle 0x00 7e 00 01
    classdata
      com.trganda.a.SerData
        values
```
对于一个序列化后对对象，序列化文件流对内容由固定头部（`STREAM_MAGIC`） + 版本（`STREAM_VERSION`） + 内容的形式组成。而对象以`TC_OBJECT`为开头进行表示，然后紧跟对象类的描述。具体包括，类名，`serialVersionUID`，对接口，注解和父类的描述。`newHandle`是为当前被序列化对对象所分配对一个唯一数值，也就是前面提到的`serial number`。
完整的序列化格式对文法定义可以参考官方文档，[Object Serialization Stream Protocol](https://docs.oracle.com/javase/8/docs/platform/serialization/spec/protocol.html)。
### 反序列化调用过程
这里仍以前面的例子分析Java反序列化的调用过程（即`readObject()`的内在逻辑）。
```java
public class Main {

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.dat"));

        SerData serData = new SerData();
        oos.writeObject(serData);

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ser.dat"));
        Object object = ois.readObject();
        System.out.println(object.toString());
    }
}
```
在第10行打下断点，跟入源码
```java
    public final Object readObject()
        throws IOException, ClassNotFoundException
    {
        if (enableOverride) {
            return readObjectOverride();
        }

        // if nested read, passHandle contains handle of enclosing object
        int outerHandle = passHandle;
        try {
            Object obj = readObject0(false);
```
`readObjectOverride()`不需要关心，只有你继承了ObjectInputStream类才可能用到它。对象的获取位于11行，继续跟入`readObject0`
```java
private Object readObject0(boolean unshared) throws IOException {
    boolean oldMode = bin.getBlockDataMode();
    if (oldMode) {
        int remain = bin.currentBlockRemaining();
        if (remain > 0) {
            throw new OptionalDataException(remain);
        } else if (defaultDataEnd) {
            /*
                 * Fix for 4360508: stream is currently at the end of a field
                 * value block written via default serialization; since there
                 * is no terminating TC_ENDBLOCKDATA tag, simulate
                 * end-of-custom-data behavior explicitly.
                 */
            throw new OptionalDataException(true);
        }
        bin.setBlockDataMode(false);
    }

    byte tc;
    while ((tc = bin.peekByte()) == TC_RESET) {
        bin.readByte();
        handleReset();
    }

    depth++;
    totalObjectRefs++;
    try {
        switch (tc) {
            case TC_NULL:
                return readNull();

            case TC_REFERENCE:
                return readHandle(unshared);

            case TC_CLASS:
                return readClass(unshared);

            case TC_CLASSDESC:
            case TC_PROXYCLASSDESC:
                return readClassDesc(unshared);

            case TC_STRING:
            case TC_LONGSTRING:
                return checkResolve(readString(unshared));

            case TC_ARRAY:
                return checkResolve(readArray(unshared));

            case TC_ENUM:
                return checkResolve(readEnum(unshared));

            case TC_OBJECT:
                return checkResolve(readOrdinaryObject(unshared));
            // more code ...
```
前面是对块输入流的状态检查，保证数据能被正确解析。之后读取首个`byte`并根据它的值进行下一步处理，由于本例序列化的是一个自己定义的类对象，代码进入`TC_OBJECT`。跟入`readOrdinaryObject()`，
```java
    private Object readOrdinaryObject(boolean unshared)
        throws IOException
    {
        if (bin.readByte() != TC_OBJECT) {
            throw new InternalError();
        }

        ObjectStreamClass desc = readClassDesc(false);
        desc.checkDeserialize();

        Class<?> cl = desc.forClass();
        if (cl == String.class || cl == Class.class
                || cl == ObjectStreamClass.class) {
            throw new InvalidClassException("invalid class descriptor");
        }

        Object obj;
        try {
            obj = desc.isInstantiable() ? desc.newInstance() : null;
        } catch (Exception ex) {
            throw (IOException) new InvalidClassException(
                desc.forClass().getName(),
                "unable to create instance").initCause(ex);
        }
        // more code ...
```
此处先从输入流中，读取创建一个`ObjectStreamClass`对象，它用于描述被序列化的类对象的一系列属性，比如是否实现了`Serializable`或`Externalizable`接口，类成员有几个，是否定义了自己的`readObject/writeObject`方法等。
最后再调用`desc.forClass()`获取`Class`对象，并通过`newInstance()`方法创建对象实例。由此，跟入`readClassDesc()`，
```java
private ObjectStreamClass readClassDesc(boolean unshared)
    throws IOException
{
    byte tc = bin.peekByte();
    ObjectStreamClass descriptor;
    switch (tc) {
        case TC_NULL:
            descriptor = (ObjectStreamClass) readNull();
            break;
        case TC_REFERENCE:
            descriptor = (ObjectStreamClass) readHandle(unshared);
            break;
        case TC_PROXYCLASSDESC:
            descriptor = readProxyDesc(unshared);
            break;
        case TC_CLASSDESC:
            descriptor = readNonProxyDesc(unshared);
            break;
        default:
            throw new StreamCorruptedException(
                String.format("invalid type code: %02X", tc));
    }
    if (descriptor != null) {
        validateDescriptor(descriptor);
    }
    return descriptor;
}
```
再到`readNonProxyDesc`，这里先不关注代理类，它们的处理逻辑是大致相似的。
```java
private ObjectStreamClass readNonProxyDesc(boolean unshared)
    throws IOException
    {
        if (bin.readByte() != TC_CLASSDESC) {
            throw new InternalError();
        }

        ObjectStreamClass desc = new ObjectStreamClass();
        int descHandle = handles.assign(unshared ? unsharedMarker : desc);
        passHandle = NULL_HANDLE;

        ObjectStreamClass readDesc = null;
        try {
            readDesc = readClassDescriptor();
        } catch (ClassNotFoundException ex) {
            throw (IOException) new InvalidClassException(
                "failed to read class descriptor").initCause(ex);
        }

        Class<?> cl = null;
        ClassNotFoundException resolveEx = null;
        bin.setBlockDataMode(true);
        final boolean checksRequired = isCustomSubclass();
        try {
            if ((cl = resolveClass(readDesc)) == null) {
                resolveEx = new ClassNotFoundException("null class");
            } else if (checksRequired) {
                ReflectUtil.checkPackageAccess(cl);
            }
        } catch (ClassNotFoundException ex) {
            resolveEx = ex;
        }

        // Call filterCheck on the class before reading anything else
        filterCheck(cl, -1);

        skipCustomData();

        try {
            totalObjectRefs++;
            depth++;
            desc.initNonProxy(readDesc, cl, resolveEx, readClassDesc(false));
        } finally {
            depth--;
        }

        handles.finish(descHandle);
        passHandle = descHandle;

        return desc;
    }
```
这里先调用`readClassDescriptor()`获取类的描述信息，再`resolveClass()`获取`class`对象。类的描述信息的读取，实际位于`readNonProxy()`。读取后调用`filterCheck()`对类进行检查并跳过`TC_ENDBLOCKDATA`前的数据。
> `filterCheck()`会调用反序列化过滤器接口`ObjectInputFilter`的实现类对象的`checkInput`方法，开发者可自己实现该接口，并通过`jdk.serialFilter`属性进行设置。

```java
void readNonProxy(ObjectInputStream in)
    throws IOException, ClassNotFoundException
    {
        name = in.readUTF();
        suid = Long.valueOf(in.readLong());
        isProxy = false;

        byte flags = in.readByte();
        hasWriteObjectData =
            ((flags & ObjectStreamConstants.SC_WRITE_METHOD) != 0);
        hasBlockExternalData =
            ((flags & ObjectStreamConstants.SC_BLOCK_DATA) != 0);
        externalizable =
            ((flags & ObjectStreamConstants.SC_EXTERNALIZABLE) != 0);
        boolean sflag =
            ((flags & ObjectStreamConstants.SC_SERIALIZABLE) != 0);
        if (externalizable && sflag) {
            throw new InvalidClassException(
                name, "serializable and externalizable flags conflict");
        }
        serializable = externalizable || sflag;
        isEnum = ((flags & ObjectStreamConstants.SC_ENUM) != 0);
        if (isEnum && suid.longValue() != 0L) {
            throw new InvalidClassException(name,
                "enum descriptor has non-zero serialVersionUID: " + suid);
        }

        int numFields = in.readShort();
        if (isEnum && numFields != 0) {
            throw new InvalidClassException(name,
                "enum descriptor has non-zero field count: " + numFields);
        }
        fields = (numFields > 0) ?
            new ObjectStreamField[numFields] : NO_FIELDS;
        for (int i = 0; i < numFields; i++) {
            char tcode = (char) in.readByte();
            String fname = in.readUTF();
            String signature = ((tcode == 'L') || (tcode == '[')) ?
                in.readTypeString() : new String(new char[] { tcode });
            try {
                fields[i] = new ObjectStreamField(fname, signature, false);
            } catch (RuntimeException e) {
                throw (IOException) new InvalidClassException(name,
                    "invalid descriptor for field " + fname).initCause(e);
            }
        }
        computeFieldOffsets();
    }
```
这里会读取类的名称，`_serialVersionUID_`和描述标记，并返回上层。
整个过程的调用栈如下：
```java
readClassDesc:1736, ObjectInputStream (java.io) [2]
readNonProxyDesc:1883, ObjectInputStream (java.io)
readClassDesc:1749, ObjectInputStream (java.io) [1]
readOrdinaryObject:2040, ObjectInputStream (java.io)
readObject0:1571, ObjectInputStream (java.io)
readObject:431, ObjectInputStream (java.io)
main:18, Main (com.trganda)
```
## 反序列化漏洞
通过前面的示例可以大致了解`Java`中的序列化实现。当`Java`在处理反序列化数据时，如果它满怀恶意则可能引起安全问题。来看一个最简单的例子
有下面一段业务逻辑代码，这看上去多少有点蠢，不过实际情况也差不太多。只是数据流更加复杂，条件更多。
```java
public class Eval implements Serializable {
    public String command;
    
    private void readObject(java.io.ObjectInputStream in)
        throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        
        Runtime.getRuntime().exec(command);
    }
}
```
在这种情况下，构造恶意的序列化数据，就可以执行恶意的命令了。
```java
public static void serialize_test(){
    Eval eval = new Eval();
    eval.command = "calc";
    try {
        FileOutputStream fos = new FileOutputStream("user.ser");
        ObjectOutputStream obs = new ObjectOutputStream(fos);
        obs.writeObject(eval);
        obs.close();
        fos.close();
    } catch (IOException e){
        e.printStackTrace();
    }
}

public static void deserialize_test() {
    try {
        FileInputStream fis = new FileInputStream("user.ser");
        ObjectInputStream ois = new ObjectInputStream(fis);
        ois.readObject();
        ois.close();
        fis.close();
    } catch (IOException | ClassNotFoundException e) {
        e.printStackTrace();
    }
}

public static void main(String[] args) {
    serialize_test();
    deserialize_test();
}
```
就像下面这样
![image.png](https://cdn.nlark.com/yuque/0/2022/png/22838900/1661504809896-b56230f6-886d-4d25-9b92-f553aeafab98.png#clientId=ue6ea6eec-ad1c-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=552&id=u46a5810d&margin=%5Bobject%20Object%5D&name=image.png&originHeight=552&originWidth=1057&originalType=binary&ratio=1&rotation=0&showTitle=false&size=64743&status=done&style=shadow&taskId=u7f5e533c-454e-4990-8383-9bb3e575351&title=&width=1057)
当`readObject`的输入流变得可控，事情就开始变得严重起来的。
### 场景
在`Java`语言的生态中反序列化的使用场景实在是太多了，简单列举

- cookie，session
- rmi、jndi、jms、jmx等
- fastjson、jackson
- xmldecoder、xstream
### Refernece

1. [Java Object Serialization (oracle.com)](https://docs.oracle.com/javase/8/docs/technotes/guides/serialization/index.html)
1. [OWASP AppSecCali 2015 - Marshalling Pickles (slideshare.net)](https://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)
1. [Exploiting Deserialization Vulnerabilities in Java (slideshare.net)](https://www.slideshare.net/codewhitesec/exploiting-deserialization-vulnerabilities-in-java-54707478)
1. [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability. (foxglovesecurity.com)](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/)
1. [https://www.oreilly.com/library/view/learning-java/1565927184/ch11s04.html](https://www.oreilly.com/library/view/learning-java/1565927184/ch11s04.html)
1. [https://paper.seebug.org/312/](https://paper.seebug.org/312/)
1. [https://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmiTOC.html](https://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmiTOC.html)
1. [https://www.ibm.com/docs/en/sdk-java-technology/8?topic=iiop-rmi-implementation](https://www.ibm.com/docs/en/sdk-java-technology/8?topic=iiop-rmi-implementation)
1. [Java 安全-RMI-学习总结](https://paper.seebug.org/1251/#rmi)
1. [JAVA RMI 反序列化知识详解](https://paper.seebug.org/1194/#java-rmi)
1. [https://blog.kaibro.tw/2020/02/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BreadObject%E5%88%86%E6%9E%90/](https://blog.kaibro.tw/2020/02/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BreadObject%E5%88%86%E6%9E%90/)
1. [https://bugs.openjdk.org/browse/JDK-4674902](https://bugs.openjdk.org/browse/JDK-4674902)






