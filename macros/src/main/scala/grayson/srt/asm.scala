package grayson.srt

import scala.language.experimental.macros

import reflect.macros.Context

import org.objectweb.asm
import asm.{Opcodes => O, ClassWriter, ClassVisitor, Handle, MethodVisitor}


object ASM5 {
  import grayson.srt.{ASM5_impl => impl}


  object method {
    def public(info: String) = macro impl.publicMethod
  }

  def begin(mv: MethodVisitor)= macro impl.begin

  type Label = org.objectweb.asm.Label
  def label = new Label
  def label(label: Label) = macro impl.label

  def nop = macro impl.nop
  def aconst_null = macro impl.aconst_null
  def iconst_m1 = macro impl.iconst_m1
  def iconst_0 = macro impl.iconst_0
  def iconst_1 = macro impl.iconst_1
  def iconst_2 = macro impl.iconst_2
  def iconst_3 = macro impl.iconst_3
  def iconst_4 = macro impl.iconst_4
  def iconst_5 = macro impl.iconst_5
  def lconst_0 = macro impl.lconst_0
  def lconst_1 = macro impl.lconst_1
  def fconst_0 = macro impl.fconst_0
  def fconst_1 = macro impl.fconst_1
  def fconst_2 = macro impl.fconst_2
  def dconst_0 = macro impl.dconst_0
  def dconst_1 = macro impl.dconst_1
  def bipush(operand: Int) = macro impl.bipush
  def sipush(operand: Int) = macro impl.sipush
  def ldc(cst: AnyRef) = macro impl.ldc
  def ldc_w(cst: AnyRef) = macro impl.ldc_w
  def ldc2_w(cst: AnyRef) = macro impl.ldc2_w
  def iload(_var: Int) = macro impl.iload
  def lload(_var: Int) = macro impl.lload
  def fload(_var: Int) = macro impl.fload
  def dload(_var: Int) = macro impl.dload
  def aload(_var: Int) = macro impl.aload
  def iload_0 = macro impl.iload_0
  def iload_1 = macro impl.iload_1
  def iload_2 = macro impl.iload_2
  def iload_3 = macro impl.iload_3
  def lload_0 = macro impl.lload_0
  def lload_1 = macro impl.lload_1
  def lload_2 = macro impl.lload_2
  def lload_3 = macro impl.lload_3
  def fload_0 = macro impl.fload_0
  def fload_1 = macro impl.fload_1
  def fload_2 = macro impl.fload_2
  def fload_3 = macro impl.fload_3
  def dload_0 = macro impl.dload_0
  def dload_1 = macro impl.dload_1
  def dload_2 = macro impl.dload_2
  def dload_3 = macro impl.dload_3
  def aload_0 = macro impl.aload_0
  def aload_1 = macro impl.aload_1
  def aload_2 = macro impl.aload_2
  def aload_3 = macro impl.aload_3
  def iaload = macro impl.iaload
  def laload = macro impl.laload
  def faload = macro impl.faload
  def daload = macro impl.daload
  def aaload = macro impl.aaload
  def baload = macro impl.baload
  def caload = macro impl.caload
  def saload = macro impl.saload
  def istore(_var: Int) = macro impl.istore
  def lstore(_var: Int) = macro impl.lstore
  def fstore(_var: Int) = macro impl.fstore
  def dstore(_var: Int) = macro impl.dstore
  def astore(_var: Int) = macro impl.astore
  def istore_0 = macro impl.istore_0
  def istore_1 = macro impl.istore_1
  def istore_2 = macro impl.istore_2
  def istore_3 = macro impl.istore_3
  def lstore_0 = macro impl.lstore_0
  def lstore_1 = macro impl.lstore_1
  def lstore_2 = macro impl.lstore_2
  def lstore_3 = macro impl.lstore_3
  def fstore_0 = macro impl.fstore_0
  def fstore_1 = macro impl.fstore_1
  def fstore_2 = macro impl.fstore_2
  def fstore_3 = macro impl.fstore_3
  def dstore_0 = macro impl.dstore_0
  def dstore_1 = macro impl.dstore_1
  def dstore_2 = macro impl.dstore_2
  def dstore_3 = macro impl.dstore_3
  def astore_0 = macro impl.astore_0
  def astore_1 = macro impl.astore_1
  def astore_2 = macro impl.astore_2
  def astore_3 = macro impl.astore_3
  def iastore = macro impl.iastore
  def lastore = macro impl.lastore
  def fastore = macro impl.fastore
  def dastore = macro impl.dastore
  def aastore = macro impl.aastore
  def bastore = macro impl.bastore
  def castore = macro impl.castore
  def sastore = macro impl.sastore
  def pop = macro impl.pop
  def pop2 = macro impl.pop2
  def dup = macro impl.dup
  def dup_x1 = macro impl.dup_x1
  def dup_x2 = macro impl.dup_x2
  def dup2 = macro impl.dup2
  def dup2_x1 = macro impl.dup2_x1
  def dup2_x2 = macro impl.dup2_x2
  def swap = macro impl.swap
  def iadd = macro impl.iadd
  def ladd = macro impl.ladd
  def fadd = macro impl.fadd
  def dadd = macro impl.dadd
  def isub = macro impl.isub
  def lsub = macro impl.lsub
  def fsub = macro impl.fsub
  def dsub = macro impl.dsub
  def imul = macro impl.imul
  def lmul = macro impl.lmul
  def fmul = macro impl.fmul
  def dmul = macro impl.dmul
  def idiv = macro impl.idiv
  def ldiv = macro impl.ldiv
  def fdiv = macro impl.fdiv
  def ddiv = macro impl.ddiv
  def irem = macro impl.irem
  def lrem = macro impl.lrem
  def frem = macro impl.frem
  def drem = macro impl.drem
  def ineg = macro impl.ineg
  def lneg = macro impl.lneg
  def fneg = macro impl.fneg
  def dneg = macro impl.dneg
  def ishl = macro impl.ishl
  def lshl = macro impl.lshl
  def ishr = macro impl.ishr
  def lshr = macro impl.lshr
  def iushr = macro impl.iushr
  def lushr = macro impl.lushr
  def iand = macro impl.iand
  def land = macro impl.land
  def ior = macro impl.ior
  def lor = macro impl.lor
  def ixor = macro impl.ixor
  def lxor = macro impl.lxor
  def iinc(index: Int, const: Int) = macro impl.iinc
  def i2l = macro impl.i2l
  def i2f = macro impl.i2f
  def i2d = macro impl.i2d
  def l2i = macro impl.l2i
  def l2f = macro impl.l2f
  def l2d = macro impl.l2d
  def f2i = macro impl.f2i
  def f2l = macro impl.f2l
  def f2d = macro impl.f2d
  def d2i = macro impl.d2i
  def d2l = macro impl.d2l
  def d2f = macro impl.d2f
  def i2b = macro impl.i2b
  def i2c = macro impl.i2c
  def i2s = macro impl.i2s
  def lcmp = macro impl.lcmp
  def fcmpl = macro impl.fcmpl
  def fcmpg = macro impl.fcmpg
  def dcmpl = macro impl.dcmpl
  def dcmpg = macro impl.dcmpg
  def ifeq(label: Label) = macro impl.ifeq
  def ifne(label: Label) = macro impl.ifne
  def iflt(label: Label) = macro impl.iflt
  def ifge(label: Label) = macro impl.ifge
  def ifgt(label: Label) = macro impl.ifgt
  def ifle(label: Label) = macro impl.ifle
  def if_icmpeq(label: Label) = macro impl.if_icmpeq
  def if_icmpne(label: Label) = macro impl.if_icmpne
  def if_icmplt(label: Label) = macro impl.if_icmplt
  def if_icmpge(label: Label) = macro impl.if_icmpge
  def if_icmpgt(label: Label) = macro impl.if_icmpgt
  def if_icmple(label: Label) = macro impl.if_icmple
  def if_acmpeq(label: Label) = macro impl.if_acmpeq
  def if_acmpne(label: Label) = macro impl.if_acmpne
  def goto(label: Label) = macro impl.goto
  def jsr(l: Label) = macro impl.jsr
  def ret(_var: Int) = macro impl.ret
  def tableswitch(min: Int, max: Int, dflt: Label, labels: Array[Label]) = macro impl.tableswitch
  def lookupswitch(keys: Array[Int], labels: Array[Label]) = macro impl.lookupswitch
  def ireturn = macro impl.ireturn
  def lreturn = macro impl.lreturn
  def freturn = macro impl.freturn
  def dreturn = macro impl.dreturn
  def areturn = macro impl.areturn
  def return_ = macro impl.return_
  def getstatic(owner: String, name: String, desc: String) = macro impl.getstatic
  def putstatic(owner: String, name: String, desc: String) = macro impl.putstatic
  def getfield(owner: String, name: String, desc: String) = macro impl.getfield
  def putfield(owner: String, name: String, desc: String) = macro impl.putfield
  def invokevirtual(owner: String, name: String, desc: String) = macro impl.invokevirtual
  def invokespecial(owner: String, name: String, desc: String) = macro impl.invokespecial
  def invokestatic(owner: String, name: String, desc: String) = macro impl.invokestatic
  def invokeinterface(owner: String, name: String, desc: String) = macro impl.invokeinterface
  def invokedynamic(name: String, desc: String, bsm: Handle, bsmArgs: Array[AnyRef]) = macro impl.invokedynamic
  def new_(_type: String) = macro impl.new_
  def newarray(operand: Int) = macro impl.newarray
  def anewarray(_type: String) = macro impl.anewarray
  def arraylength = macro impl.arraylength
  def athrow = macro impl.athrow
  def checkcast(_type: String) = macro impl.checkcast
  def instanceof(_type: String) = macro impl.instanceof
  def monitorenter = macro impl.monitorenter
  def monitorexit = macro impl.monitorexit
  def multianewarray(desc: String, dims: Int) = macro impl.multianewarray
  def ifnull(label: Label) = macro impl.ifnull
  def ifnonnull(label: Label) = macro impl.ifnonnull
  def goto_w(label: Label) = macro impl.goto_w
  def jsr_w(label: Label) = macro impl.jsr_w

}

object ASM5_impl {
  import ASM5._



  def publicMethod(c: Context)(info: c.Expr[String]) = maker(c).publicMethod(info)

  def begin(c: Context)(mv: c.Expr[MethodVisitor]) = maker(c).begin(mv)

  def label(c: Context)(label: c.Expr[Label]) = maker(c) label label

  def nop(c: Context)         = maker(c) insn O.NOP
  def aconst_null(c: Context) = maker(c) insn O.ACONST_NULL
  def iconst_m1(c: Context)   = maker(c) insn O.ICONST_M1
  def iconst_0(c: Context)    = maker(c) insn O.ICONST_0
  def iconst_1(c: Context)    = maker(c) insn O.ICONST_1
  def iconst_2(c: Context)    = maker(c) insn O.ICONST_2
  def iconst_3(c: Context)    = maker(c) insn O.ICONST_3
  def iconst_4(c: Context)    = maker(c) insn O.ICONST_4
  def iconst_5(c: Context)    = maker(c) insn O.ICONST_5
  def lconst_0(c: Context)    = maker(c) insn O.LCONST_0
  def lconst_1(c: Context)    = maker(c) insn O.LCONST_1
  def fconst_0(c: Context)    = maker(c) insn O.FCONST_0
  def fconst_1(c: Context)    = maker(c) insn O.FCONST_1
  def fconst_2(c: Context)    = maker(c) insn O.FCONST_2
  def dconst_0(c: Context)    = maker(c) insn O.DCONST_0
  def dconst_1(c: Context)    = maker(c) insn O.DCONST_1
  def bipush(c: Context)(operand: c.Expr[Int])  = maker(c) intInsn (O.BIPUSH, operand)
  def sipush(c: Context)(operand: c.Expr[Int])  = maker(c) intInsn(O.SIPUSH, operand)
  def ldc(c: Context)(cst: c.Expr[AnyRef])      = maker(c) ldcInsn cst
  def ldc_w(c: Context)(cst: c.Expr[AnyRef])    = maker(c) ldcInsn cst
  def ldc2_w(c: Context)(cst: c.Expr[AnyRef])   = maker(c) ldcInsn cst
  def iload(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.ILOAD, _var)
  def lload(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.LLOAD, _var)
  def fload(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.FLOAD, _var)
  def dload(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.DLOAD, _var)
  def aload(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.ALOAD, _var)
  def iload_0(c: Context) = maker(c) insn 26
  def iload_1(c: Context) = maker(c) insn 27
  def iload_2(c: Context) = maker(c) insn 28
  def iload_3(c: Context) = maker(c) insn 29
  def lload_0(c: Context) = maker(c) insn 30
  def lload_1(c: Context) = maker(c) insn 31
  def lload_2(c: Context) = maker(c) insn 32
  def lload_3(c: Context) = maker(c) insn 33
  def fload_0(c: Context) = maker(c) insn 34
  def fload_1(c: Context) = maker(c) insn 35
  def fload_2(c: Context) = maker(c) insn 36
  def fload_3(c: Context) = maker(c) insn 37
  def dload_0(c: Context) = maker(c) insn 38
  def dload_1(c: Context) = maker(c) insn 39
  def dload_2(c: Context) = maker(c) insn 40
  def dload_3(c: Context) = maker(c) insn 41
  def aload_0(c: Context) = maker(c) insn 42
  def aload_1(c: Context) = maker(c) insn 43
  def aload_2(c: Context) = maker(c) insn 44
  def aload_3(c: Context) = maker(c) insn 45
  def iaload(c: Context) = maker(c) insn O.IALOAD
  def laload(c: Context) = maker(c) insn O.LALOAD
  def faload(c: Context) = maker(c) insn O.FALOAD
  def daload(c: Context) = maker(c) insn O.DALOAD
  def aaload(c: Context) = maker(c) insn O.AALOAD
  def baload(c: Context) = maker(c) insn O.BALOAD
  def caload(c: Context) = maker(c) insn O.CALOAD
  def saload(c: Context) = maker(c) insn O.SALOAD
  def istore(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.ISTORE, _var)
  def lstore(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.LSTORE, _var)
  def fstore(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.FSTORE, _var)
  def dstore(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.DSTORE, _var)
  def astore(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.ASTORE, _var)
  def istore_0(c: Context) = maker(c) insn 59
  def istore_1(c: Context) = maker(c) insn 60
  def istore_2(c: Context) = maker(c) insn 61
  def istore_3(c: Context) = maker(c) insn 62
  def lstore_0(c: Context) = maker(c) insn 63
  def lstore_1(c: Context) = maker(c) insn 64
  def lstore_2(c: Context) = maker(c) insn 65
  def lstore_3(c: Context) = maker(c) insn 66
  def fstore_0(c: Context) = maker(c) insn 67
  def fstore_1(c: Context) = maker(c) insn 68
  def fstore_2(c: Context) = maker(c) insn 69
  def fstore_3(c: Context) = maker(c) insn 70
  def dstore_0(c: Context) = maker(c) insn 71
  def dstore_1(c: Context) = maker(c) insn 72
  def dstore_2(c: Context) = maker(c) insn 73
  def dstore_3(c: Context) = maker(c) insn 74
  def astore_0(c: Context) = maker(c) insn 75
  def astore_1(c: Context) = maker(c) insn 76
  def astore_2(c: Context) = maker(c) insn 77
  def astore_3(c: Context) = maker(c) insn 78
  def iastore(c: Context) = maker(c) insn O.IASTORE
  def lastore(c: Context) = maker(c) insn O.LASTORE
  def fastore(c: Context) = maker(c) insn O.FASTORE
  def dastore(c: Context) = maker(c) insn O.DASTORE
  def aastore(c: Context) = maker(c) insn O.AASTORE
  def bastore(c: Context) = maker(c) insn O.BASTORE
  def castore(c: Context) = maker(c) insn O.CASTORE
  def sastore(c: Context) = maker(c) insn O.SASTORE
  def pop(c: Context) = maker(c) insn O.POP
  def pop2(c: Context) = maker(c) insn O.POP2
  def dup(c: Context) = maker(c) insn O.DUP
  def dup_x1(c: Context) = maker(c) insn O.DUP_X1
  def dup_x2(c: Context) = maker(c) insn O.DUP_X2
  def dup2(c: Context) = maker(c) insn O.DUP2
  def dup2_x1(c: Context) = maker(c) insn O.DUP2_X1
  def dup2_x2(c: Context) = maker(c) insn O.DUP2_X2
  def swap(c: Context) = maker(c) insn O.SWAP
  def iadd(c: Context) = maker(c) insn O.IADD
  def ladd(c: Context) = maker(c) insn O.LADD
  def fadd(c: Context) = maker(c) insn O.FADD
  def dadd(c: Context) = maker(c) insn O.DADD
  def isub(c: Context) = maker(c) insn O.ISUB
  def lsub(c: Context) = maker(c) insn O.LSUB
  def fsub(c: Context) = maker(c) insn O.FSUB
  def dsub(c: Context) = maker(c) insn O.DSUB
  def imul(c: Context) = maker(c) insn O.IMUL
  def lmul(c: Context) = maker(c) insn O.LMUL
  def fmul(c: Context) = maker(c) insn O.FMUL
  def dmul(c: Context) = maker(c) insn O.DMUL
  def idiv(c: Context) = maker(c) insn O.IDIV
  def ldiv(c: Context) = maker(c) insn O.LDIV
  def fdiv(c: Context) = maker(c) insn O.FDIV
  def ddiv(c: Context) = maker(c) insn O.DDIV
  def irem(c: Context) = maker(c) insn O.IREM
  def lrem(c: Context) = maker(c) insn O.LREM
  def frem(c: Context) = maker(c) insn O.FREM
  def drem(c: Context) = maker(c) insn O.DREM
  def ineg(c: Context) = maker(c) insn O.INEG
  def lneg(c: Context) = maker(c) insn O.LNEG
  def fneg(c: Context) = maker(c) insn O.FNEG
  def dneg(c: Context) = maker(c) insn O.DNEG
  def ishl(c: Context) = maker(c) insn O.ISHL
  def lshl(c: Context) = maker(c) insn O.LSHL
  def ishr(c: Context) = maker(c) insn O.ISHR
  def lshr(c: Context) = maker(c) insn O.LSHR
  def iushr(c: Context) = maker(c) insn O.IUSHR
  def lushr(c: Context) = maker(c) insn O.LUSHR
  def iand(c: Context) = maker(c) insn O.IAND
  def land(c: Context) = maker(c) insn O.LAND
  def ior(c: Context) = maker(c) insn O.IOR
  def lor(c: Context) = maker(c) insn O.LOR
  def ixor(c: Context) = maker(c) insn O.IXOR
  def lxor(c: Context) = maker(c) insn O.LXOR
  def iinc(c: Context)(index: c.Expr[Int], const: c.Expr[Int]) = maker(c) iincInsn (index, const)
  def i2l(c: Context) = maker(c) insn O.I2L
  def i2f(c: Context) = maker(c) insn O.I2F
  def i2d(c: Context) = maker(c) insn O.I2D
  def l2i(c: Context) = maker(c) insn O.L2I
  def l2f(c: Context) = maker(c) insn O.L2F
  def l2d(c: Context) = maker(c) insn O.L2D
  def f2i(c: Context) = maker(c) insn O.F2I
  def f2l(c: Context) = maker(c) insn O.F2L
  def f2d(c: Context) = maker(c) insn O.F2D
  def d2i(c: Context) = maker(c) insn O.D2I
  def d2l(c: Context) = maker(c) insn O.D2L
  def d2f(c: Context) = maker(c) insn O.D2F
  def i2b(c: Context) = maker(c) insn O.I2B
  def i2c(c: Context) = maker(c) insn O.I2C
  def i2s(c: Context) = maker(c) insn O.I2S
  def lcmp(c: Context) = maker(c) insn O.LCMP
  def fcmpl(c: Context) = maker(c) insn O.FCMPL
  def fcmpg(c: Context) = maker(c) insn O.FCMPG
  def dcmpl(c: Context) = maker(c) insn O.DCMPL
  def dcmpg(c: Context) = maker(c) insn O.DCMPG
  def ifeq(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IFEQ, label)
  def ifne(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IFNE, label)
  def iflt(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IFLT, label)
  def ifge(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IFGE, label)
  def ifgt(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IFGT, label)
  def ifle(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IFLE, label)
  def if_icmpeq(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IF_ICMPEQ, label)
  def if_icmpne(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IF_ICMPNE, label)
  def if_icmplt(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IF_ICMPLT, label)
  def if_icmpge(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IF_ICMPGE, label)
  def if_icmpgt(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IF_ICMPGT, label)
  def if_icmple(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IF_ICMPLE, label)
  def if_acmpeq(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IF_ACMPEQ, label)
  def if_acmpne(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IF_ACMPNE, label)
  def goto(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.GOTO, label)
  def jsr(c: Context)(l: c.Expr[Label]) = maker(c) jumpInsn (O.JSR, l)
  def ret(c: Context)(_var: c.Expr[Int]) = maker(c) varInsn (O.RET, _var)
  def tableswitch(c: Context)(min: c.Expr[Int], max: c.Expr[Int], dflt: c.Expr[Label], labels: c.Expr[Array[Label]]) =
    maker(c) tableSwitchInsn (min, max, dflt, labels)
  def lookupswitch(c: Context)(keys: c.Expr[Array[Int]], labels: c.Expr[Array[Label]]) =
    maker(c) lookupSwitchInsn (keys, labels)
  def ireturn(c: Context) = maker(c) insn O.IRETURN
  def lreturn(c: Context) = maker(c) insn O.LRETURN
  def freturn(c: Context) = maker(c) insn O.FRETURN
  def dreturn(c: Context) = maker(c) insn O.DRETURN
  def areturn(c: Context) = maker(c) insn O.ARETURN
  def return_(c: Context) = maker(c) insn O.RETURN
  def getstatic(c: Context)(owner: c.Expr[String], name: c.Expr[String], desc: c.Expr[String]) =
    maker(c) fieldInsn (O.GETSTATIC, owner, name, desc)
  def putstatic(c: Context)(owner: c.Expr[String], name: c.Expr[String], desc: c.Expr[String]) =
    maker(c) fieldInsn (O.PUTSTATIC, owner, name, desc)
  def getfield(c: Context)(owner: c.Expr[String], name: c.Expr[String], desc: c.Expr[String]) =
    maker(c) fieldInsn (O.GETFIELD, owner, name, desc)
  def putfield(c: Context)(owner: c.Expr[String], name: c.Expr[String], desc: c.Expr[String]) =
    maker(c) fieldInsn (O.PUTFIELD, owner, name, desc)
  def invokevirtual(c: Context)(owner: c.Expr[String], name: c.Expr[String], desc: c.Expr[String]) =
    maker(c) methodInsn (O.INVOKEVIRTUAL, owner, name, desc)
  def invokespecial(c: Context)(owner: c.Expr[String], name: c.Expr[String], desc: c.Expr[String]) =
    maker(c) methodInsn (O.INVOKESPECIAL, owner, name, desc)
  def invokestatic(c: Context)(owner: c.Expr[String], name: c.Expr[String], desc: c.Expr[String]) =
    maker(c) methodInsn (O.INVOKESTATIC, owner, name, desc)
  def invokeinterface(c: Context)(owner: c.Expr[String], name: c.Expr[String], desc: c.Expr[String]) =
    maker(c) methodInsn (O.INVOKEINTERFACE, owner, name, desc)
  def invokedynamic(c: Context)(name: c.Expr[String], desc: c.Expr[String], bsm: c.Expr[Handle], bsmArgs: c.Expr[Array[AnyRef]]) =
    maker(c) invokeDynamicInsn (name, desc, bsm, bsmArgs)
  def new_(c: Context)(_type: c.Expr[String]) = maker(c) typeInsn (O.NEW, _type)
  def newarray(c: Context)(operand: c.Expr[Int]) = maker(c) intInsn (O.NEWARRAY, operand)
  def anewarray(c: Context)(_type: c.Expr[String]) = maker(c) typeInsn (O.ANEWARRAY, _type)
  def arraylength(c: Context) = maker(c) insn O.ARRAYLENGTH
  def athrow(c: Context) = maker(c) insn O.ATHROW
  def checkcast(c: Context)(_type: c.Expr[String]) = maker(c) typeInsn (O.CHECKCAST, _type)
  def instanceof(c: Context)(_type: c.Expr[String]) = maker(c) typeInsn (O.INSTANCEOF, _type)
  def monitorenter(c: Context) = maker(c) insn O.MONITORENTER
  def monitorexit(c: Context) = maker(c) insn O.MONITOREXIT
  def multianewarray(c: Context)(desc: c.Expr[String], dims: c.Expr[Int]) = maker(c) multiANewArrayInsn (desc, dims)
  def ifnull(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IFNULL, label)
  def ifnonnull(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (O.IFNONNULL, label)
  def goto_w(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (200, label)
  def jsr_w(c: Context)(label: c.Expr[Label]) = maker(c) jumpInsn (201, label)

  implicit def maker(c: Context) = new ASMMaker[c.type](c)

  /**
   * Utility that emits instructions against the ASM library
   * @param c the macro context
   * @tparam C
   */
  class ASMMaker[C <: Context](val c: C) {
    import c.universe._
    import c.Expr

    trait Payload
    case class MVPayload(mv: Expr[MethodVisitor]) extends Payload
    case class CVPayload(cv: Expr[ClassVisitor]) extends Payload

    /** Associates the payload with the enclosing method or the enclosing
      * class if no method is available.
      * @param payload
      */
    def setPayload[P <: Payload](payload: P) {
      if (c.enclosingMethod != null)
        c.enclosingMethod.updateAttachment(payload)
      else
        c.enclosingClass.updateAttachment(payload)
    }

    /** Gets the payload associated with the nearest enclosing method or
      * the enclosing class if no method is available.
      * @return
      */
    def getPayload[P <: Payload] = {
      if (c.enclosingMethod != null)
        c.enclosingMethod.attachments.get[P]
      else
        c.enclosingClass.attachments.get[P]
    }

    def mvFunc(name: String, args: Seq[Any]) = getPayload match {
      case Some(payload) =>
        Expr(Apply(
          Select(payload.mv.tree, newTermName(name)),
          args
            .map { _ match {
            case expr: Expr[_] => expr.tree
            case any => Literal(Constant(any))
          }}
            .toList
        ))

      case None =>
        c.error(c.enclosingPosition, "No MethodVisitor set")
        c.literalUnit
    }


    def begin(mv: Expr[MethodVisitor]): Expr[Unit] = {
      setPayload(Payload(mv))
      c.literalUnit
    }

    def label(args: Any*)               = mvFunc("visitLabel", args)
    def insn(args: Any*)                = mvFunc("visitInsn", args)
    def intInsn(args: Any*)             = mvFunc("visitIntInsn", args)
    def ldcInsn(args: Any*)             = mvFunc("visitLdcInsn", args)
    def varInsn(args: Any*)             = mvFunc("visitVarInsn", args)
    def iincInsn(args: Any*)            = mvFunc("visitIincInsn", args)
    def jumpInsn(args: Any*)            = mvFunc("visitJumpInsn", args)
    def tableSwitchInsn(args: Any*)     = mvFunc("visitTableSwitchInsn", args)
    def lookupSwitchInsn(args: Any*)    = mvFunc("visitLookupSwitchInsn", args)
    def fieldInsn(args: Any*)           = mvFunc("visitFieldInsn", args)
    def methodInsn(args: Any*)          = mvFunc("visitMethodInsn", args)
    def invokeDynamicInsn(args: Any*)   = mvFunc("visitInvokeDynamicInsn", args)
    def typeInsn(args: Any*)            = mvFunc("visitTypeInsn", args)
    def multiANewArrayInsn(args: Any*)  = mvFunc("visitMultiANewArrayInsn", args)
  }

}



trait AsmContainer {
  def start(cw: ClassWriter)
  def end(cw: ClassWriter)
}

case class ClassDef(val name: String) extends AsmContainer {

  def superType: String = null

  override def start(cw: ClassWriter) {
    cw.visit(49, O.ACC_PUBLIC, name, null, superType, null)
  }

  override def end(cw: ClassWriter) {
    cw.visitEnd
  }
}


trait FieldDef
trait MethodDef