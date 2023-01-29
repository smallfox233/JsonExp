**作者：** 小狐狸FM

**项目：** 

**版本：** 1.0

**简介：** 

```
根据现有payload，检测目标是否存在fastjson漏洞（工具仅用于检测漏洞）
若存在漏洞，可根据对应payload进行后渗透利用
若出现新的漏洞时，可将最新的payload新增至txt中（需修改格式）
```

**使用：**



```
JsonExp -u [目标] -l [LDAP服务地址]  -f fastjson.txt
```

![](1.png)

若出现dnslog回弹，可根据前面的编号去寻找对应的payload

```
编号.LDAP地址
```



![](2.png)

![](3.png)



**payload介绍：**

```
1. 每行分为两个部分，一个是漏洞利用的payload，另一个部分是注释
2. payload必须写在注释的前面
3. 注释符#及其之后的内容，将会在检测时被忽略
4. 若payload为多行，则需将其中的换行符删去，保证一个payload占据一行
```



```
$type$	用于指定ldap或rmi服务类型
$ip$	用于指定ldap地址或rmi地址
```





