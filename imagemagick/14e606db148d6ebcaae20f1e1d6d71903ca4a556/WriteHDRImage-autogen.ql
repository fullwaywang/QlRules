/**
 * @name imagemagick-14e606db148d6ebcaae20f1e1d6d71903ca4a556-WriteHDRImage
 * @id cpp/imagemagick/14e606db148d6ebcaae20f1e1d6d71903ca4a556/WriteHDRImage
 * @description imagemagick-14e606db148d6ebcaae20f1e1d6d71903ca4a556-coders/hdr.c-WriteHDRImage CVE-2016-7520
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_658, ExprStmt target_3, ExprStmt target_4) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_658
		and target_0.getAnOperand().(Literal).getValue()="128"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_658
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getValue()="4"
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vimage_658, Variable vpixels_686, ExprStmt target_5, RelationalOperation target_6, EqualityOperation target_7, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ResetMagickMemory")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixels_686
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_658
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="128"
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(35)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(35).getFollowingStmt()=target_1)
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vimage_658, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="columns"
		and target_2.getQualifier().(VariableAccess).getTarget()=vimage_658
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getValue()="4"
}

predicate func_3(Parameter vimage_658, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("WriteBlob")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_658
}

predicate func_4(Parameter vimage_658, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_4.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_658
}

predicate func_5(Parameter vimage_658, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_658
}

predicate func_6(Parameter vimage_658, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_658
}

predicate func_7(Variable vpixels_686, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vpixels_686
		and target_7.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vimage_658, Variable vpixels_686, PointerFieldAccess target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6, EqualityOperation target_7
where
not func_0(vimage_658, target_3, target_4)
and not func_1(vimage_658, vpixels_686, target_5, target_6, target_7, func)
and func_2(vimage_658, target_2)
and func_3(vimage_658, target_3)
and func_4(vimage_658, target_4)
and func_5(vimage_658, target_5)
and func_6(vimage_658, target_6)
and func_7(vpixels_686, target_7)
and vimage_658.getType().hasName("Image *")
and vpixels_686.getType().hasName("unsigned char *")
and vimage_658.getParentScope+() = func
and vpixels_686.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
