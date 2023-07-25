/**
 * @name ffmpeg-944f5b2779e4aa63f7624df6cd4de832a53db81b-sbr_qmf_synthesis
 * @id cpp/ffmpeg/944f5b2779e4aa63f7624df6cd4de832a53db81b/sbr-qmf-synthesis
 * @description ffmpeg-944f5b2779e4aa63f7624df6cd4de832a53db81b-libavcodec/aacsbr.c-sbr_qmf_synthesis CVE-2012-0850
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="128"
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getCondition() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vdiv_1184, BlockStmt target_4, ConditionalExpr target_5, BinaryBitwiseOperation target_6) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand() instanceof PointerDereferenceExpr
		and target_1.getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="128"
		and target_1.getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vdiv_1184
		and target_1.getParent().(IfStmt).getThen()=target_4
		and target_5.getCondition().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getRightOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vv_off_1184, BlockStmt target_4, PointerDereferenceExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vv_off_1184
		and target_2.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(BlockStmt target_4, Function func, EqualityOperation target_3) {
		target_3.getAnOperand() instanceof PointerDereferenceExpr
		and target_3.getAnOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_4
		and target_3.getEnclosingFunction() = func
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("float *")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("float *")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

predicate func_5(Parameter vdiv_1184, ConditionalExpr target_5) {
		target_5.getCondition().(VariableAccess).getTarget()=vdiv_1184
		and target_5.getThen().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_5.getElse().(VariableAccess).getTarget().getType() instanceof ArrayType
}

predicate func_6(Parameter vdiv_1184, BinaryBitwiseOperation target_6) {
		target_6.getLeftOperand().(SubExpr).getValue()="1152"
		and target_6.getRightOperand().(VariableAccess).getTarget()=vdiv_1184
}

from Function func, Parameter vv_off_1184, Parameter vdiv_1184, Literal target_0, PointerDereferenceExpr target_2, EqualityOperation target_3, BlockStmt target_4, ConditionalExpr target_5, BinaryBitwiseOperation target_6
where
func_0(func, target_0)
and not func_1(vdiv_1184, target_4, target_5, target_6)
and func_2(vv_off_1184, target_4, target_2)
and func_3(target_4, func, target_3)
and func_4(target_4)
and func_5(vdiv_1184, target_5)
and func_6(vdiv_1184, target_6)
and vv_off_1184.getType().hasName("int *")
and vdiv_1184.getType().hasName("const unsigned int")
and vv_off_1184.getFunction() = func
and vdiv_1184.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
