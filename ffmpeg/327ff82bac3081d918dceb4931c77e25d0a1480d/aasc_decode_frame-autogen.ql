/**
 * @name ffmpeg-327ff82bac3081d918dceb4931c77e25d0a1480d-aasc_decode_frame
 * @id cpp/ffmpeg/327ff82bac3081d918dceb4931c77e25d0a1480d/aasc-decode-frame
 * @description ffmpeg-327ff82bac3081d918dceb4931c77e25d0a1480d-libavcodec/aasc.c-aasc_decode_frame CVE-2013-2496
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_65, PointerArithmeticOperation target_5, AddressOfExpr target_6) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("bytestream2_init")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
		and target_0.getArgument(1) instanceof PointerArithmeticOperation
		and target_0.getArgument(2) instanceof AddExpr
		and target_5.getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_65, Parameter vavctx_59, VariableAccess target_7, ExprStmt target_8, MulExpr target_9, ExprStmt target_10) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_59
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
		and target_1.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_1.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_1.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vs_65, Parameter vavctx_59, AddressOfExpr target_6, ExprStmt target_8) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_59
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof PointerArithmeticOperation
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof AddExpr
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_3(Variable vbuf_63, Variable vbuf_size_64, Variable vs_65, Parameter vavctx_59, PointerArithmeticOperation target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vbuf_63
		and target_3.getRightOperand().(Literal).getValue()="4"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_59
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuf_size_64
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(Literal).getValue()="4"
}

/*predicate func_4(Variable vbuf_63, Variable vbuf_size_64, Variable vs_65, Parameter vavctx_59, AddExpr target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vbuf_size_64
		and target_4.getAnOperand().(Literal).getValue()="4"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_59
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vbuf_63
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="4"
}

*/
predicate func_5(Variable vs_65, PointerArithmeticOperation target_5) {
		target_5.getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_5.getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_5.getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
		and target_5.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="linesize"
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_6(Variable vs_65, AddressOfExpr target_6) {
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
}

predicate func_7(Variable vcompr_66, VariableAccess target_7) {
		target_7.getTarget()=vcompr_66
}

predicate func_8(Variable vs_65, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("void *")
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="frame"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_65
}

predicate func_9(Parameter vavctx_59, MulExpr target_9) {
		target_9.getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_9.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_59
		and target_9.getRightOperand().(Literal).getValue()="3"
}

predicate func_10(Variable vcompr_66, Parameter vavctx_59, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_59
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_10.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unknown compression type %d\n"
		and target_10.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcompr_66
}

from Function func, Variable vbuf_63, Variable vbuf_size_64, Variable vs_65, Variable vcompr_66, Parameter vavctx_59, PointerArithmeticOperation target_3, PointerArithmeticOperation target_5, AddressOfExpr target_6, VariableAccess target_7, ExprStmt target_8, MulExpr target_9, ExprStmt target_10
where
not func_0(vs_65, target_5, target_6)
and not func_1(vs_65, vavctx_59, target_7, target_8, target_9, target_10)
and func_3(vbuf_63, vbuf_size_64, vs_65, vavctx_59, target_3)
and func_5(vs_65, target_5)
and func_6(vs_65, target_6)
and func_7(vcompr_66, target_7)
and func_8(vs_65, target_8)
and func_9(vavctx_59, target_9)
and func_10(vcompr_66, vavctx_59, target_10)
and vbuf_63.getType().hasName("const uint8_t *")
and vbuf_size_64.getType().hasName("int")
and vs_65.getType().hasName("AascContext *")
and vcompr_66.getType().hasName("int")
and vavctx_59.getType().hasName("AVCodecContext *")
and vbuf_63.(LocalVariable).getFunction() = func
and vbuf_size_64.(LocalVariable).getFunction() = func
and vs_65.(LocalVariable).getFunction() = func
and vcompr_66.(LocalVariable).getFunction() = func
and vavctx_59.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
