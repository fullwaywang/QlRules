/**
 * @name imagemagick-3a7e63bc27e3e84cec4617125fa7641d77b90e65-ReadPALMImage
 * @id cpp/imagemagick/3a7e63bc27e3e84cec4617125fa7641d77b90e65/ReadPALMImage
 * @description imagemagick-3a7e63bc27e3e84cec4617125fa7641d77b90e65-coders/palm.c-ReadPALMImage CVE-2017-9407
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vone_row_282, RelationalOperation target_8) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vone_row_282
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vone_row_282
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8)
}

predicate func_1(Variable vcompressionType_265, Variable vlastrow_281, RelationalOperation target_8, EqualityOperation target_9, ExprStmt target_10) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcompressionType_265
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlastrow_281
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlastrow_281
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_3(Variable vcompressionType_265, Variable vlastrow_281, EqualityOperation target_11) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcompressionType_265
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlastrow_281
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlastrow_281
		and target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vone_row_282, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vone_row_282
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vone_row_282
}

predicate func_5(Variable vcompressionType_265, Variable vlastrow_281, IfStmt target_5) {
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcompressionType_265
		and target_5.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlastrow_281
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlastrow_281
}

predicate func_6(EqualityOperation target_12, Function func, EmptyStmt target_6) {
		target_6.toString() = ";"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Function func, EmptyStmt target_7) {
		target_7.toString() = ";"
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Variable vone_row_282, RelationalOperation target_8) {
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vone_row_282
}

predicate func_9(Variable vcompressionType_265, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vcompressionType_265
		and target_9.getAnOperand().(Literal).getValue()="0"
}

predicate func_10(Variable vlastrow_281, Variable vone_row_282, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("CopyMagickMemory")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlastrow_281
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vone_row_282
}

predicate func_11(Variable vcompressionType_265, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vcompressionType_265
		and target_11.getAnOperand().(Literal).getValue()="0"
}

predicate func_12(EqualityOperation target_12) {
		target_12.getAnOperand().(Literal).getValue()="16"
}

from Function func, Variable vcompressionType_265, Variable vlastrow_281, Variable vone_row_282, ExprStmt target_4, IfStmt target_5, EmptyStmt target_6, EmptyStmt target_7, RelationalOperation target_8, EqualityOperation target_9, ExprStmt target_10, EqualityOperation target_11, EqualityOperation target_12
where
not func_0(vone_row_282, target_8)
and not func_1(vcompressionType_265, vlastrow_281, target_8, target_9, target_10)
and not func_3(vcompressionType_265, vlastrow_281, target_11)
and func_4(vone_row_282, target_4)
and func_5(vcompressionType_265, vlastrow_281, target_5)
and func_6(target_12, func, target_6)
and func_7(func, target_7)
and func_8(vone_row_282, target_8)
and func_9(vcompressionType_265, target_9)
and func_10(vlastrow_281, vone_row_282, target_10)
and func_11(vcompressionType_265, target_11)
and func_12(target_12)
and vcompressionType_265.getType().hasName("size_t")
and vlastrow_281.getType().hasName("unsigned char *")
and vone_row_282.getType().hasName("unsigned char *")
and vcompressionType_265.getParentScope+() = func
and vlastrow_281.getParentScope+() = func
and vone_row_282.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
