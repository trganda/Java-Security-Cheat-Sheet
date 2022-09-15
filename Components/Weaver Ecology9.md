## 安装教程
首先需要安装MSSQL，具体安装教程自行上网搜索，安装后记录好`sa`账户名和密码，并启用`TCP`链接。
第一步，配置hosts文件将`update.e-cology.cn`和`www.weaver.com.cn`指向`127.0.0.1`，阻止补丁的自动更新。
> 这是Share文件中，1907版本的安装方式。如果你想装朋友给你的1904版本，在完成下面这些步骤后，删掉已有的ecology目录（注意是删除，不是覆盖），再把你朋友那个解压拿过来就行。

第二步，安装`winrar`，默认安装即可。
第三步，运行，`Ecology_setup_forWindows_v2.61`。选择全新安装，它会将`ecology`和`resin`自动解压到当前目录下，并提示你配置`resin`，跟着控制台提示走即可。
第四步，配置`Resin`
运行resin目录下的`setup.exe`，创建服务，这一步可选。
之后确保`conf/resin.xml`中的以下内容所设路径正确
```xml
<javac compiler="C:\Program Files\Java\jdk1.8.0_65\bin\javac" args="-encoding UTF-8"/>

<web-app id="/" root-directory="C:\Users\Administrator\Desktop\e9\ecology">
  <servlet-mapping url-pattern='/weaver/*' servlet-name='invoker'/>
  <form-parameter-max>100000</form-parameter-max>
</web-app>
```
以及`resinstart.bat`中的`java_home`环境变量设置正确，且与上面的`javac`相符
```bash
set java_home=C:\Program Files\Java\jdk1.8.0_65
resin.exe
```
## 组件指纹
`Set-Cookie: ecology_JSessionId=`
## 调试方式
泛微`E9`默认使用`Resin`作为容器，在`Resin`目录下`/conf/resin.properties`文件中找到`jvm_args`参数，在参数值中加入
```java
-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005
```
之后在`IDEA`或其它`IDE`中将如下目录内容添加进`Lib`

- `ecology/classbean`
- `ecology/WEB-INF/classes`
- `ecology/WEB-INF/classes/lib`
- `ecology/WEB-INF/classes/lib-soap`
- `ecology/WEB-INF/classes/lib-soapui`
- `ecology/WEB-INF/classes/lib_reader`

这些目录包含大部分的`class`文件和`jar`包
## 常用文件和数据

- 环境安装验证码：`/ecology/WEB-INF/code.key`文件中（`wEAver2018`）。
- 管理员账号：位于数据表`HrmResourceManager`，密码为`md5`加密，无法解码的情况下，可以直接修改此表的`password`列的值（注意字母需要大写）。默认密码为`1`或`Weaver@2001`。
- 环境信息查看：访问`/security/monitor/Monitor.jsp`，包含操作系统版本、`ecology`版本、`web`中间件版本、`JVM`版本、客户端软件和规则库版本（需要登录）。
- 编译后的`class`文件：`/ecology/classbean/` 文件夹下
- 系统运行依赖的`jar`：`/ecology/WEB-INF/lib/` 文件夹下
## 路由
### /weaver
默认的服务器`Resin`，查看其resin.xml，配置了`invoker servlet`，即一种默认访问`servlet`的方式，可以运行没有在`web.xml`中配置的servlet。访问路径为`/weaver/*`，`*`后是被访问的`Java`类的全限定名称，此类需要直接或间接实现`Servlet`或`HttpServlet`相关接口。
```xml
<web-app id="/" root-directory="C:\Users\Administrator\Desktop\Ecology1907\ecology">
  <servlet-mapping url-pattern='/weaver/*' servlet-name='invoker'/>
  <form-parameter-max>100000</form-parameter-max>
</web-app>
```
所以`lib`目录下的bsh-2.0b4.jar可以按照全限定类名`/bsh.servlet.BshServlet`访问`BshServlet`类，该类实现了`HttpServlet`接口
```java
public class BshServlet extends HttpServlet {
    public void doGet(HttpServletRequest var1, HttpServletResponse var2) throws ServletException, IOException {
        String var3 = var1.getParameter("bsh.script");
        ...
            var8 = this.evalScript(var3, var10, var7, var1, var2);
    }
}
```
### /xx.jsp
`jsp`文件的访问路径均为`ecology`根目录到该`jsp`的路径，例如`jsp`的绝对路为`ecology/addressbook/AddressBook.jsp`，那么该`jsp`的访问路径为`http://ip:port/addressbook/AddressBook.jsp`
### /services/*
`/services/*`的服务配置由`org.codehaus.xfire.transport.http.XFireConfigurableServlet`读取`classbean/META-INF/xfire/services.xml`文件进行加载创建。配置文件各服务节点结构大致如下
```xml
<service> 
  <name>DocService</name>  
  <namespace>http://localhost/services/DocService</namespace>  
  <serviceClass>weaver.docs.webservices.DocService</serviceClass>  
  <implementationClass>weaver.docs.webservices.DocServiceImpl</implementationClass>  
  <serviceFactory>org.codehaus.xfire.annotations.AnnotationServiceFactory</serviceFactory> 
</service>
```
### /api/*
由`@Path`注解定义的一系列`REST`接口，可以在`ecology/WEB-INF/Api.xls`文件中查看所有的`api/`接口路径和相关类。泛微从`E9`版本开始新增了`/api`路由，在旧版本中，该路由存在大小写绕过鉴权的漏洞。
### /*.do
由实现了`weaver.interfaces.workflow.action.Action`接口的`action`来处理，配置文件位于`ecology/WEB-INF/service/*.xml`
```xml
<action path="/getProcess" type="com.weaver.action.EcologyUpgrade" parameter="getProcess" >
</action>
```
可通过`/<path>.do`的方式访问。
## 安全策略
安全策略由如下过滤器执行
```xml
<filter>
    <filter-name>SecurityFilter</filter-name>
    <filter-class>weaver.filter.SecurityFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>SecurityFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```
安全策略的具体内容分为两种，规则形式的`xml`文件（位于`WEB-INF/securityRule`），和实现`weaver.security.rules.BaseRule`接口的类（位于`WEB-INF/myclasses/weaver/security/rules/ruleImp`）。
### 加载过程
安全策略的加载位于`SecurityMain#initFilterBean`方法，加载顺序如下

- 加载`WEB-INF/weaver_security_config.xml`
- 加载`WEB-INF/weaver_security_rules.xml`
- 加载`WEB-INF/securityRule/{Ecology_Version}/*.xml`，并将这些文件作为参数调用`ruleImp`中实现了`BaseRule`接口的自定义规则的`init`函数
- 从数据库表`weaver_security_rules`中加载（如果配置文件中的`fromDB=db`）
- 调用`ruleImp`中实现了`BaseRule`接口的自定义规则的`initConfig`函数
- 加载`WEB-INF/securityRule/Rule/*.xml`
- 加载`WEB-INF/securityXML/*.xml`

安全补丁的日志位于`/ecology/WEB-INF/securitylog`。
### 特征
如果由于安全策略导致请求失败，都会由`errorRedirect`函数处理，它的内容如下，所用可以通过这个函数的逻辑，快速判断你的请求是否是被安全策略拦截了。
```java
    public void errorRedirect(HttpServletRequest var1, HttpServletResponse var2, String var3, boolean var4) throws IOException {
        SecurityCore var6 = new SecurityCore();
        String var7 = var1.getRequestURI();
        if (!"".equals(var6.null2String(var6.getRule().get("intercept-code"))) && !"isLogin".equals(var3) && !var3.equals("securityInitFailed")) {
            var2.addHeader("errorMsg", "security intercept:" + var3);
            var2.sendError(var6.getIntValue("" + var6.getRule().get("intercept-code"), 404));
        } else if (!var3.equals("referCheck") && !var3.equals("referEmpty")) {
            if (var7 != null && var7.startsWith("/api/")) {
                JSONObject var9 = new JSONObject();
                var9.put("status", false);
                if (var3.equals("isLogin")) {
                    var9.put("msg", "登录超时");
                    var9.put("errorCode", "002");
                } else if (var3.equals("securityInitFailed")) {
                    var9.put("msg", "安全包初始化失败，系统处于不受保护状态。具体信息请 查看日志：/ecology/WEB-INF/securitylog/systemRunInfo" + (new XssUtil()).getStartDate() + ".log");
                    var9.put("errorCode", "-001");
                } else if (var3.equals("forgetPassword")) {
                    var9.put("msg", "忘记密码功能已被禁用,请联系系统管理员!");
                    var9.put("errorCode", "-002");
                } else if (var3.equals("isWhiteIp")) {
                    var9.put("msg", "非法IP，禁止访问系统!");
                    var9.put("errorCode", "-003");
                } else if (var3.equals("isCookieMatchIp")) {
                    var9.put("msg", "您无权访问该资源,请联系系统管理员!");
                    var9.put("errorCode", "-004");
                } else if (var3.equals("hostCheck")) {
                    var9.put("msg", "服务器主机伪造,阻断该请求!");
                    var9.put("errorCode", "-005");
                } else if (var3.equals("checkUrlCheatPass")) {
                    var9.put("msg", "疑似钓鱼欺骗,阻断该请求!");
                    var9.put("errorCode", "-006");
                } else if (var3.equals("webservice")) {
                    var9.put("msg", "非法IP调用webservice,阻断该请求!");
                    var9.put("errorCode", "-007");
                } else if (var3.equals("isAllowIp")) {
                    var9.put("msg", "非法IP,禁止访问系统!");
                    var9.put("errorCode", "-008");
                } else if (var3.equals("checkSpecialRule")) {
                    var9.put("msg", "提示:系统错误.");
                    var9.put("errorCode", "-009");
                }

                var2.setContentType("text/html; charset=utf-8");
                var2.getWriter().println(var9.toString());
            } else {
                String var8 = var6.null2String(var1.getParameter("gopage"));
                if (!"".equals(var8)) {
                    var8 = ESAPI.encodeForSQL(var8);
                    var8 = ESAPI.encodeForHTML(var8);
                }

                var4 = false;
                if (!var4) {
                    if (var3.equals("forgetPassword")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"忘记密码功能已被禁用,请联系系统管理员!\");}catch(e){alert(\"忘记密码功能已被禁用,请联系系统管理员!\");}</script>";
                    }

                    if (var3.equals("isLogin")) {
                        var3 = "<script type='text/javascript'>try{top.location.href='/login/Login.jsp?gopage=" + var8 + "&_token_=" + UUID.randomUUID().toString() + "';}catch(e){window.location.href='/login/Login.jsp?gopage=" + var8 + "&_token_=" + UUID.randomUUID().toString() + "';}</script>";
                    }

                    if (var3.equals("isWhiteIp")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"非法IP，禁止访问系统!\");}catch(e){alert(\"非法IP，禁止访问系统!\");}</script>";
                    }

                    if (var3.equals("isCookieMatchIp")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"您无权访问该资源,请联系系统管理员!\");}catch(e){alert(\"您无权访问该资源,请联系系统管理员!!\");}</script>";
                    }

                    if (var3.equals("hostCheck")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"服务器主机伪造,阻断该请求!\");}catch(e){alert(\"服务器主机伪造,阻断该请求!\");}</script>";
                    }

                    if (var3.equals("forbbidenUrl")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"您无权访问该资源,请联系系统管理员!\");}catch(e){alert(\"您无权访问该资源,请联系系统管理员!!\");}</script>";
                    }

                    if (var3.equals("checkUrlCheatPass")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"疑似钓鱼欺骗,阻断该请求!\");}catch(e){alert(\"疑似钓鱼欺骗,阻断该请求!\");}</script>";
                    }

                    if (var3.equals("referCheck")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"疑似跨站点请求攻击,阻断该请求!\");}catch(e){alert(\"疑似跨站点请求攻击,阻断该请求!\");};window.history.go(-1);</script>";
                    }

                    if (var3.equals("referEmpty")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"疑似跨站点请求攻击,阻断该请求!\");}catch(e){alert(\"疑似跨站点请求攻击,阻断该请求!\");};window.history.go(-1);</script>";
                    }

                    if (var3.equals("webservice")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"非法IP调用webservice,阻断该请求!\");}catch(e){alert(\"非法IP调用webservice,阻断该请求!\");}</script>";
                    }

                    if (var3.equals("isAllowIp")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"非法IP,禁止访问系统!\");}catch(e){alert(\"非法IP，禁止访问系统!\");}</script>";
                    }

                    if (var3.equals("checkSpecialRule")) {
                        var3 = "<script language='javascript'>try{top.Dialog.alert(\"提示:系统错误.\");}catch(e){alert(\"提示:系统错误.\");}window.history.go(-1);</script>";
                    }

                    var2.setContentType("text/html; charset=utf-8");
                    var2.getWriter().println(var3);
                }

            }
        } else {
            var2.sendError(403);
        }
    }
```
安全策略生效特征：

1. URL访问404，响应头部包含`errorMsg: securityIntercept`
1. 访问后弹窗，提示登录或出错，或响应体中包含`<script type='text/javascript'>try{top.location.href='/login/Login.jsp?af=1&_token_=`
### 通用规则
参数名称过滤策略
`ecology/WEB-INF/securityRule/Rule/weaver_security_custom_rules_for_20180411.xml`
```xml
<param-key>^(?!.*(&lt;|&gt;|&amp;|'|"|\(|\)|\r|\n|%0D%0A)).*$</param-key>
```
SQL注入过滤策略
`/ecology/WEB-INF/securityRule/Rule/weaver_security_for_sqlinjection_rules.xml`
```xml
<rules>
  <!--破坏性sql语句检查-->
  <rule>exec[^a-zA-Z]|insert[^a-zA-Z]into[^a-zA-Z].*?values|delete[^a-zA-Z].*?from|update[^a-zA-Z].*?set|truncate[^a-zA-Z]</rule>
  <!--常见注入字符检查-->
  <rule>[^a-zA-Z]count\(|[^a-zA-Z]chr\(|[^a-zA-Z]mid\(|[^a-zA-Z]char[\s+\(]|[^a-zA-Z]net[^a-zA-Z]user[^a-zA-Z]|[^a-zA-Z]xp_cmdshell[^a-zA-Z]|\W/add\W|[^a-zA-Z]master\.dbo\.xp_cmdshell|net[^a-zA-Z]localgroup[^a-zA-Z]administrators|DBMS_PIPE\.|[^a-zA-Z]len\s*\(|[^a-zA-Z]left\s*\(|[^a-zA-Z]right\s*\(|str(c|ing)?\s*\(|ascii\s*\(|UNION([^a-zA-Z]ALL[^a-zA-Z])?SELECT[^a-zA-Z]NULL|[a-zA-Z0-9_\-]+\s*=\s*0x(2D|3[0-9]|4[1-F1-f]|5[1-A1-a]|6[1-F1-f]|7[1-A][1-a])|UTL_HTTP\s*\(|MAKE_SET\s*\(|ELTs*\(|IIF\s*\(|(PG_)?SLEEP\s*\(|DBMS_LOCK\s*\.|USER_LOCK\s*\.|[LR]LIKE\s*\(|CONCAT(_WS)?\s*\(|GREATEST\s*\(|IF(NULL)?\s*\(|EXTRACTVALUE\s*\(|UPDATEXML\s*\(|WAITFOR\s*DELAY|ANALYSE\s*\(|UNION\s+(ALL\s+)?SELECT</rule>
  <!--typical SQL injection detect-->
  <rule>\w*((\%27))((\%6F)|(\%4F))((\%72)|(\%52))</rule>
  <rule>((\%27)|('))union</rule>
  <rule>substrb\(</rule>
</rules>
```
安全策略的处理逻辑大致如下，未覆盖所有代码分支
![](https://cdn.nlark.com/yuque/0/2022/jpeg/22838900/1660211652784-80f76abc-8213-4a42-acbf-6826967cc0c2.jpeg)
## 关闭补丁的自动更新
就漏洞分析来讲，自动更新补丁会打乱节奏。可以通过修改`hosts`文件的方式来应对，让泛微无法访问`update.e-cology.cn`，比如让它指向`127.0.0.1`。
补丁密码

- v10.39-46：Weaver@Ecology201205 
- <v10.38：未知 
- old version：Weaver#2012!@#
## 历史漏洞
### BeanShell RCE (2019.09.17修复)
POST /weaver/bsh.servlet.BshServlet
### Soap XStream RCE 
POST /services%20/WorkflowServiceXml
Ref: [https://www.anquanke.com/post/id/239865](https://www.anquanke.com/post/id/239865)
### 前台Zip文件上传
POST /weaver/weaver.common.Ctrl/.css?arg0=com.cloudstore.api.service.Service_CheckApp&arg1=validateApp
GET /cloudstore/xxx.jsp
### 文件上传
POST /weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image
Ref: [https://mp.weixin.qq.com/s?__biz=MzkxMzIzNTU5Mg==&mid=2247483666&idx=1&sn=e70efe98c064e0f1df986e2b65c1a608&chksm=c1018af5f67603e39ce4d6e9375875e63e7b80633a1f99959f8d4652193ac3734765a99099ea&mpshare=1&scene=23&srcid=0414cqXy50udQOy19LYOMega&sharer_sharetime=1618332600979&sharer_shareid=d15208c7b27f111e2fe465f389ab6fac#rd](https://mp.weixin.qq.com/s?__biz=MzkxMzIzNTU5Mg==&mid=2247483666&idx=1&sn=e70efe98c064e0f1df986e2b65c1a608&chksm=c1018af5f67603e39ce4d6e9375875e63e7b80633a1f99959f8d4652193ac3734765a99099ea&mpshare=1&scene=23&srcid=0414cqXy50udQOy19LYOMega&sharer_sharetime=1618332600979&sharer_shareid=d15208c7b27f111e2fe465f389ab6fac#rd)
### 文件上传
POST /weaver/weaver.workflow.exceldesign.ExcelUploadServlet?method=uploadFile&savefile=pass.jsp
Ref:[https://mp.weixin.qq.com/s?__biz=MzkxMzIzNTU5Mg==&mid=2247483674&idx=1&sn=ce1c56a670587df0a33201a62a4b6e2d&chksm=c1018afdf67603eb15bea96e668bc0279b63f241654beb000da3c7e7333d8545c4c3217d0576&scene=178&cur_album_id=1824092566640705544#rd](https://mp.weixin.qq.com/s?__biz=MzkxMzIzNTU5Mg==&mid=2247483674&idx=1&sn=ce1c56a670587df0a33201a62a4b6e2d&chksm=c1018afdf67603eb15bea96e668bc0279b63f241654beb000da3c7e7333d8545c4c3217d0576&scene=178&cur_album_id=1824092566640705544#rd)
### 数据库配置文件读取 (2019.10.24修复)
POST /mobile/DBconfigReader.jsp
### Oracle注入 (2019.10.10修复)
/mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333
### 日志泄漏
/hrm/kq/gethrmkq.jsp?filename=1
### 文件上传 （2022.06.18修复）
POST /workrelate/plan/util/uploaderOperate.jsp
POST /OfficeServer
### Cookie泄露
POST /mobile/plugin/VerifyQuickLogin.jsp
### SQL注入
GET /api/ec/dev/locale/getLabelByModule
### 代码执行
POST /api/integration/workflowflow/getInterfaceRegisterCustomOperation
### 文件读取
GET /weaver/org.springframework.web.servlet.ResourceServlet?resource=/WEB-INF/prop/weaver.properties
### SQL注入
/cpt/manage/validate.jsp

与杜老师的对话记录
Q：思考题1:/weaver/[bsh.servlet.Bs](http://bsh.servlet.bs/)hServlet。从代码审计的角度，如何找到这个路由
A：好问题，在完全不知情的情况下，我也没很好的思路，会先看它[web.xm](http://web.xm/)l，了解一下路由结构和具体java类的关系。
杜老师的回答让我觉得我对容器特性的理解还不够。我们不必着急查看`web.xml`。许多`Java Web`容器会有一个特点，提供一个名为`invoker`（或其它名称）的`servlet`，`tomcat`默认关闭，但泛微中所用的`resin`却开启了它，位于`resin.xml`中。
```xml
<web-app id="/" root-directory="C:\WEAVER\ecology">
  <servlet-mapping url-pattern='/weaver/*' servlet-name='invoker'/>
  <form-parameter-max>100000</form-parameter-max>
</web-app>
```
通过这个`servlet`，只要某个类继承了`HttpServlet`，就可以通过类全限定名称的方式访问到它，比如`/weaver/bsh.servlet.BshServlet`。

