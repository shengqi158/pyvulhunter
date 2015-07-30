# python 代码审计工具readme

python audit tool  

---
# 1,python的语法树  
根据王垠的python静态分析工具[PySonar](https://github.com/yinwang0/pysonar2)得到静态语法树，这是一个庞大的dict结构，递归去除一些不必要的参数得到稍微简单点的一个语法树，以免影响后续分析。
简单说明一下一个函数的实现，首先是”type”:”FunctionDef”表明这一段代码是函数定义，函数中则会有args，表明函数的参数，lineno是代码所在的行，name是函数名。更详细的接口文档见
https://greentreesnakes.readthedocs.org/en/latest/nodes.html 在这里包含了各个结构的定义，分析整个树就可以依照这个来实现。
# 2,基本原理

基本实现原理就是寻找危险函数和可控参数,危险函数有eval,system,popen等系统函数，同时也有咱们自定义的包含这些危险函数的函数，如果这些函数的参数是可控的，就会认为这行代码是有注入风险的，那么这个函数也是有注入风险的.

对于可控参数，首先会从函数参数入手，认为函数参数是可控的，分析程序会根据前面的语法树去分析代码结构，发现有将函数参数赋值的操作，并且这个赋值是简单的转换，这些简单的转换包含如下类型：
  * （1） 简单的取属性，如get取值，对request单独处理，只认为GET,POST,FILES可控，其他request字段如META,user,session,url等都是不可控的。
  * （2） 字符串拼接，被拼接的字符串中包含可控参数，则认为赋值后的值也是可控的
  * （3） 列表解析式，如果列表解析式是基于某个可控因子进行迭代的，则认为赋值后的列表也是可控的
  * （4） 分片符取值，一般认为分片后的值也是可控的，当然这个也不绝对。
  * （5） 一般的函数处理过程：a,函数是常见的字符串操作函数（str，encode，strip等）或者是简单的未过滤函数；b,处理属性；c,如果经过了未知的函数处理则将赋值后的值从可控列表中去掉。
  * （6） 如果代码中的if中有exists，isdigit等带可控参数的的return语句，则将该参数从可控参数列表中去掉（if not os.path.isdir(parentPath)：return None），或者将可控参数定死在某个范围之内的（if type not in ["R", "B"]：return HttpResponse("2")）

# 3,使用方法  
  使用方法如下：
  liaoxinxi$ python judge_injection.py -h
  Usage: judge_injection.py [options]

  Options:
  -h, --help            show this help message and exit
  -d FILE_PATH, --dir=FILE_PATH
  files to be checked
  -c, --cmd             cmd check
  -s, --sql             sql check
  -a, --all             cmd check and sql check
  -v, --verbose         print all unsafe func

默认是对所有情况进行检查，包括代码注入，sql注入，命令注入，xss注入，危险的文件操作等

# 4,代码结构
judge_injection类负责分析文件，得到一个python语法树，提炼出代码中包含的函数语句，分析每一行代码在碰到函数的时候会调用look_up_arg函数，该函数会得出函数中的可变变量，如果可变变量在危险函数中出现了就认为该外层调用函数是危险的。

# 5,详细设计文档
参见https://github.com/shengqi158/pyvulhunter/blob/master/python_audit.pdf


