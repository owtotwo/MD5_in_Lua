# **MD5_in_Lua** #
A MD5-encryption library implemented in Lua-5.3 .  
__*Copyright (c) 2016 sysu_AT < owtotwo@163.com >*__  


## How to Use ##

Just use `md5.lua` for your project and require this file.  

```
md5 = require "md5"

print(md5.string("abc")) -- "900150983cd24fb0d6963f7d28e17f72"
print(md5.file("date.txt")) -- output the md5 value to the file "data.txt"
```

*Notice that this library is recommended to be used to encrypt the string or  
some small file which is not larger than 5MB.*  

## License ##
* GNU Lesser General Public License ([LGPL](LICENSE))  
  http://www.gnu.org/licenses/lgpl-3.0.en.html
