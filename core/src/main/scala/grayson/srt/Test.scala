package grayson.srt

import org.objectweb.asm
import asm.ClassWriter
import asm.MethodVisitor
import asm.Opcodes


object Test extends App {

  val cl = new DynamicClassLoader()

  val c = cl.loadClass("java.util.Map")

  val cv = new ClassWriter(0)

  val methodViz = cv.visitMethod(Opcodes.ACC_PUBLIC, "notify", "(Ljava/lang/String;)V", null, null)


  methodViz.

  import ASM5._
  val l_3 = label
  val l_10 = label
  val l_25 = label






  //begin(methodViz)



  method public "<init>()V"

  goto (l_10)
  label(l_3)
  iload_2
  iinc (2, 1)
  iload_1
  idiv
  istore_1

  label (l_10)
  iload_1
  iload_2
  if_icmplt (l_3)
  goto (l_25)
  astore_3
  bipush (10)
  istore_1
  goto (l_10)

  label (l_25)
  iload_2
  return_


}