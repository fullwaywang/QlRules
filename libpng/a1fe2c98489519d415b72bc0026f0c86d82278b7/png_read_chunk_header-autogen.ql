/**
 * @name libpng-a1fe2c98489519d415b72bc0026f0c86d82278b7-png_read_chunk_header
 * @id cpp/libpng/a1fe2c98489519d415b72bc0026f0c86d82278b7/png-read-chunk-header
 * @description libpng-a1fe2c98489519d415b72bc0026f0c86d82278b7-pngrutil.c-png_read_chunk_header CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vpng_ptr_156, ExprStmt target_10, ExprStmt target_11) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_2.getLesserOperand().(DivExpr).getLeftOperand() instanceof UnaryMinusExpr
		and target_2.getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getParent().(IfStmt).getThen()=target_10
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vlimit_187, RelationalOperation target_8, ExprStmt target_11) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_187
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_3.getParent().(IfStmt).getCondition()=target_8
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vpng_ptr_156, Variable vlimit_187, RelationalOperation target_8, ExprStmt target_10) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_187
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_4.getParent().(IfStmt).getCondition()=target_8
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_5(EqualityOperation target_12, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_5.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_5.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="5"
		and target_5.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_5.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="32566"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(EqualityOperation target_12, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition() instanceof RelationalOperation
		and target_7.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_7))
}

predicate func_8(Variable vlength_159, Variable vlimit_187, ExprStmt target_10, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getGreaterOperand().(VariableAccess).getTarget()=vlength_159
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vlimit_187
		and target_8.getParent().(IfStmt).getThen()=target_10
}

predicate func_9(Function func, UnaryMinusExpr target_9) {
		target_9.getValue()="-1"
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Parameter vpng_ptr_156, RelationalOperation target_8, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
		and target_10.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
		and target_10.getParent().(IfStmt).getCondition()=target_8
}

predicate func_11(Parameter vpng_ptr_156, Variable vlimit_187, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_187
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
}

predicate func_12(Parameter vpng_ptr_156, EqualityOperation target_12) {
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="chunk_name"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_12.getAnOperand().(BitwiseOrExpr).getValue()="1229209940"
}

from Function func, Parameter vpng_ptr_156, Variable vlength_159, Variable vlimit_187, RelationalOperation target_8, UnaryMinusExpr target_9, ExprStmt target_10, ExprStmt target_11, EqualityOperation target_12
where
not func_2(vpng_ptr_156, target_10, target_11)
and not func_3(vlimit_187, target_8, target_11)
and not func_4(vpng_ptr_156, vlimit_187, target_8, target_10)
and not func_5(target_12, func)
and not func_6(target_12, func)
and not func_7(func)
and func_8(vlength_159, vlimit_187, target_10, target_8)
and func_9(func, target_9)
and func_10(vpng_ptr_156, target_8, target_10)
and func_11(vpng_ptr_156, vlimit_187, target_11)
and func_12(vpng_ptr_156, target_12)
and vpng_ptr_156.getType().hasName("png_structrp")
and vlength_159.getType().hasName("png_uint_32")
and vlimit_187.getType().hasName("png_alloc_size_t")
and vpng_ptr_156.getParentScope+() = func
and vlength_159.getParentScope+() = func
and vlimit_187.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
