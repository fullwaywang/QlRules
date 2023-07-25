/**
 * @name ffmpeg-327ff82bac3081d918dceb4931c77e25d0a1480d-msrle_decode_frame
 * @id cpp/ffmpeg/327ff82bac3081d918dceb4931c77e25d0a1480d/msrle-decode-frame
 * @description ffmpeg-327ff82bac3081d918dceb4931c77e25d0a1480d-libavcodec/msrle.c-msrle_decode_frame CVE-2013-2496
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_77, Variable vbuf_size_78, Variable vs_79, ExprStmt target_5, ExprStmt target_6, ReturnStmt target_7, ExprStmt target_8, AddressOfExpr target_9) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("bytestream2_init")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_0.getArgument(1).(VariableAccess).getTarget()=vbuf_77
		and target_0.getArgument(2).(VariableAccess).getTarget()=vbuf_size_78
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(2).(VariableAccess).getLocation())
		and target_0.getArgument(2).(VariableAccess).getLocation().isBefore(target_7.getExpr().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_79, Parameter vavctx_73, EqualityOperation target_10, ExprStmt target_11, BitwiseAndExpr target_12) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_73
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="bits_per_coded_sample"
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_73
		and target_1.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_1.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vbuf_77, Variable vbuf_size_78, Variable vs_79, Parameter vavctx_73, AddressOfExpr target_9, ExprStmt target_11) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_73
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="bits_per_coded_sample"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_73
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_77
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbuf_size_78
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_3(Variable vbuf_77, Variable vbuf_size_78, Variable vs_79, Parameter vavctx_73, VariableAccess target_3) {
		target_3.getTarget()=vbuf_77
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_73
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="bits_per_coded_sample"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_73
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbuf_size_78
}

/*predicate func_4(Variable vbuf_77, Variable vbuf_size_78, Variable vs_79, Parameter vavctx_73, VariableAccess target_4) {
		target_4.getTarget()=vbuf_size_78
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_73
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="bits_per_coded_sample"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_73
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_77
}

*/
predicate func_5(Variable vbuf_77, Variable vs_79, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuf_77
}

predicate func_6(Variable vbuf_size_78, Variable vs_79, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuf_size_78
}

predicate func_7(Variable vbuf_size_78, ReturnStmt target_7) {
		target_7.getExpr().(VariableAccess).getTarget()=vbuf_size_78
}

predicate func_8(Variable vs_79, ExprStmt target_8) {
		target_8.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="linesize"
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_9(Variable vs_79, AddressOfExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
}

predicate func_10(Parameter vavctx_73, EqualityOperation target_10) {
		target_10.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_10.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_73
		and target_10.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVPacket *")
}

predicate func_11(Variable vs_79, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("void *")
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="frame"
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_79
}

predicate func_12(Parameter vavctx_73, BitwiseAndExpr target_12) {
		target_12.getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_73
		and target_12.getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vbuf_77, Variable vbuf_size_78, Variable vs_79, Parameter vavctx_73, VariableAccess target_3, ExprStmt target_5, ExprStmt target_6, ReturnStmt target_7, ExprStmt target_8, AddressOfExpr target_9, EqualityOperation target_10, ExprStmt target_11, BitwiseAndExpr target_12
where
not func_0(vbuf_77, vbuf_size_78, vs_79, target_5, target_6, target_7, target_8, target_9)
and not func_1(vs_79, vavctx_73, target_10, target_11, target_12)
and func_3(vbuf_77, vbuf_size_78, vs_79, vavctx_73, target_3)
and func_5(vbuf_77, vs_79, target_5)
and func_6(vbuf_size_78, vs_79, target_6)
and func_7(vbuf_size_78, target_7)
and func_8(vs_79, target_8)
and func_9(vs_79, target_9)
and func_10(vavctx_73, target_10)
and func_11(vs_79, target_11)
and func_12(vavctx_73, target_12)
and vbuf_77.getType().hasName("const uint8_t *")
and vbuf_size_78.getType().hasName("int")
and vs_79.getType().hasName("MsrleContext *")
and vavctx_73.getType().hasName("AVCodecContext *")
and vbuf_77.(LocalVariable).getFunction() = func
and vbuf_size_78.(LocalVariable).getFunction() = func
and vs_79.(LocalVariable).getFunction() = func
and vavctx_73.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
