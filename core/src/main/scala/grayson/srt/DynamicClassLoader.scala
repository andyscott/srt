package grayson.srt

import java.security.SecureClassLoader;

class DynamicClassLoader(parent: ClassLoader) extends SecureClassLoader(parent) {

  def this() = this(null)
  
  def _defineClass(name: String, bytes: Array[Byte])
    = defineClass(name, bytes, 0, bytes.length)

}