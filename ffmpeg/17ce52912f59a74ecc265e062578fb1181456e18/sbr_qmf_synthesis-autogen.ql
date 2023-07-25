/**
 * @name ffmpeg-17ce52912f59a74ecc265e062578fb1181456e18-sbr_qmf_synthesis
 * @id cpp/ffmpeg/17ce52912f59a74ecc265e062578fb1181456e18/sbr-qmf-synthesis
 * @description ffmpeg-17ce52912f59a74ecc265e062578fb1181456e18-libavcodec/aacsbr.c-sbr_qmf_synthesis CVE-2012-0850
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_7, Function func) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand() instanceof PointerDereferenceExpr
		and target_0.getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_0.getEnclosingFunction() = func)
}

predicate func_3(Parameter vv_off_1180, BlockStmt target_7, PointerDereferenceExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vv_off_1180
		and target_3.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_4(Parameter vdiv_1180, BinaryBitwiseOperation target_4) {
		target_4.getLeftOperand().(Literal).getValue()="128"
		and target_4.getRightOperand().(VariableAccess).getTarget()=vdiv_1180
}

predicate func_5(BlockStmt target_7, Function func, EqualityOperation target_5) {
		target_5.getAnOperand() instanceof PointerDereferenceExpr
		and target_5.getAnOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen()=target_7
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Parameter vv_off_1180, Parameter vdiv_1180, ExprStmt target_8, ExprStmt target_9, IfStmt target_10, BinaryBitwiseOperation target_6) {
		target_6.getLeftOperand().(Literal).getValue()="128"
		and target_6.getRightOperand().(VariableAccess).getTarget()=vdiv_1180
		and target_6.getParent().(AssignSubExpr).getRValue() = target_6
		and target_6.getParent().(AssignSubExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vv_off_1180
		and target_8.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_6.getParent().(AssignSubExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_6.getParent().(AssignSubExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_6.getRightOperand().(VariableAccess).getLocation().isBefore(target_10.getCondition().(VariableAccess).getLocation())
}

predicate func_7(BlockStmt target_7) {
		target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("float *")
		and target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("float *")
		and target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_7.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

predicate func_8(Parameter vv_off_1180, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vv_off_1180
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(MulExpr).getValue()="2304"
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand() instanceof BinaryBitwiseOperation
}

predicate func_9(Parameter vv_off_1180, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("float *")
		and target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("float *")
		and target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vv_off_1180
}

predicate func_10(Parameter vdiv_1180, IfStmt target_10) {
		target_10.getCondition().(VariableAccess).getTarget()=vdiv_1180
		and target_10.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="32"
		and target_10.getThen().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getElse().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getElse().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_10.getElse().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getElse().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="64"
		and target_10.getElse().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getElse().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(AssignAddExpr).getRValue().(Literal).getValue()="2"
}

from Function func, Parameter vv_off_1180, Parameter vdiv_1180, PointerDereferenceExpr target_3, BinaryBitwiseOperation target_4, EqualityOperation target_5, BinaryBitwiseOperation target_6, BlockStmt target_7, ExprStmt target_8, ExprStmt target_9, IfStmt target_10
where
not func_0(target_7, func)
and func_3(vv_off_1180, target_7, target_3)
and func_4(vdiv_1180, target_4)
and func_5(target_7, func, target_5)
and func_6(vv_off_1180, vdiv_1180, target_8, target_9, target_10, target_6)
and func_7(target_7)
and func_8(vv_off_1180, target_8)
and func_9(vv_off_1180, target_9)
and func_10(vdiv_1180, target_10)
and vv_off_1180.getType().hasName("int *")
and vdiv_1180.getType().hasName("const unsigned int")
and vv_off_1180.getFunction() = func
and vdiv_1180.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
