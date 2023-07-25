/**
 * @name libpng-095b4ce16bb46acb259ea1a4ca6562a623e58d93-png_read_chunk_header
 * @id cpp/libpng/095b4ce16bb46acb259ea1a4ca6562a623e58d93/png-read-chunk-header
 * @description libpng-095b4ce16bb46acb259ea1a4ca6562a623e58d93-pngrutil.c-png_read_chunk_header CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_159, Variable vlimit_160, ExprStmt target_10, RelationalOperation target_1) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("printf")
		and target_0.getArgument(0).(StringLiteral).getValue()=" length = %lu, limit = %lu\n"
		and target_0.getArgument(1).(VariableAccess).getTarget()=vlength_159
		and target_0.getArgument(2).(VariableAccess).getTarget()=vlimit_160
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_0.getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlength_159, Variable vlimit_160, BlockStmt target_12, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vlength_159
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vlimit_160
		and target_1.getParent().(IfStmt).getThen()=target_12
}

predicate func_2(Variable vlimit_160, RelationalOperation target_5, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_2.getParent().(IfStmt).getCondition()=target_5
}

predicate func_3(Variable vlimit_160, VariableAccess target_3) {
		target_3.getTarget()=vlimit_160
}

predicate func_4(EqualityOperation target_13, Function func, DeclStmt target_4) {
		target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Variable vrow_factor_199, Parameter vpng_ptr_156, ExprStmt target_2, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_5.getLesserOperand().(DivExpr).getLeftOperand().(UnaryMinusExpr).getValue()="-1"
		and target_5.getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_199
		and target_5.getParent().(IfStmt).getThen()=target_2
}

predicate func_6(Variable vlimit_160, Variable vrow_factor_199, Parameter vpng_ptr_156, RelationalOperation target_5, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_199
		and target_6.getParent().(IfStmt).getCondition()=target_5
}

predicate func_7(Variable vlimit_160, AssignAddExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_7.getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_7.getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="5"
		and target_7.getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vlimit_160
		and target_7.getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="32566"
}

predicate func_8(Variable vlimit_160, EqualityOperation target_13, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_160
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_160
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_9(Parameter vpng_ptr_156, Function func, IfStmt target_9) {
		target_9.getCondition() instanceof RelationalOperation
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Variable vlength_159, Parameter vpng_ptr_156, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_159
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("png_get_uint_31")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
}

predicate func_12(Parameter vpng_ptr_156, BlockStmt target_12) {
		target_12.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_12.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
		and target_12.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
}

predicate func_13(Parameter vpng_ptr_156, EqualityOperation target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="chunk_name"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_13.getAnOperand().(BitwiseOrExpr).getValue()="1229209940"
}

from Function func, Variable vlength_159, Variable vlimit_160, Variable vrow_factor_199, Parameter vpng_ptr_156, RelationalOperation target_1, ExprStmt target_2, VariableAccess target_3, DeclStmt target_4, RelationalOperation target_5, ExprStmt target_6, AssignAddExpr target_7, ExprStmt target_8, IfStmt target_9, ExprStmt target_10, BlockStmt target_12, EqualityOperation target_13
where
not func_0(vlength_159, vlimit_160, target_10, target_1)
and func_1(vlength_159, vlimit_160, target_12, target_1)
and func_2(vlimit_160, target_5, target_2)
and func_3(vlimit_160, target_3)
and func_4(target_13, func, target_4)
and func_5(vrow_factor_199, vpng_ptr_156, target_2, target_5)
and func_6(vlimit_160, vrow_factor_199, vpng_ptr_156, target_5, target_6)
and func_7(vlimit_160, target_7)
and func_8(vlimit_160, target_13, target_8)
and func_9(vpng_ptr_156, func, target_9)
and func_10(vlength_159, vpng_ptr_156, target_10)
and func_12(vpng_ptr_156, target_12)
and func_13(vpng_ptr_156, target_13)
and vlength_159.getType().hasName("png_uint_32")
and vlimit_160.getType().hasName("png_alloc_size_t")
and vrow_factor_199.getType().hasName("size_t")
and vpng_ptr_156.getType().hasName("png_structrp")
and vlength_159.getParentScope+() = func
and vlimit_160.getParentScope+() = func
and vrow_factor_199.getParentScope+() = func
and vpng_ptr_156.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
