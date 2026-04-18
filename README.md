# Red-Team-Dedicated-Scanner

这是我第一个用来学习的 go 项目
首先先做一个扫描器，然后是写一个 c2


```text
Red-Team-Dedicated-Scanner/
├─cmd               // 程序入口
│  └─scanner        
├─internal
│  ├─config         // 配置文件 
│  ├─engine         // 核心引擎
│  ├─module         // 模块
│  └─output         // 输出格式化
└─rules
    └─services      // YAML 指纹规则文件
```

TODO:
- 端口扫描系统 
- 重构，把功能分清楚
- debug 模式 
- 扫描结果的存储 