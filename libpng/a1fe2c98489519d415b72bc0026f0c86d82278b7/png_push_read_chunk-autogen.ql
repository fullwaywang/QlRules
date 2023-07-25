/**
 * @name libpng-a1fe2c98489519d415b72bc0026f0c86d82278b7-png_push_read_chunk
 * @id cpp/libpng/a1fe2c98489519d415b72bc0026f0c86d82278b7/png-push-read-chunk
 * @description libpng-a1fe2c98489519d415b72bc0026f0c86d82278b7-pngpread.c-png_push_read_chunk CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vpng_ptr_167, Variable vchunk_name_169, Variable vlimit_228, EqualityOperation target_8, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchunk_name_169
		and target_1.getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="1229209940"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand() instanceof UnaryMinusExpr
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_228
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_228
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlimit_228
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="32566"
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_228
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_228
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_228
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and target_1.getElse().(BlockStmt).getStmt(0) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1)
		and target_8.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vpng_ptr_167, Variable vlimit_228, EqualityOperation target_9, LogicalAndExpr target_10) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand() instanceof UnaryMinusExpr
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_228
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_2.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_228
		and target_2.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_2.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_3(Variable vlimit_228, EqualityOperation target_9) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlimit_228
		and target_3.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_3.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="5"
		and target_3.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vlimit_228
		and target_3.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="32566"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9)
}

*/
/*predicate func_4(Variable vlimit_228, EqualityOperation target_9) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_228
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_228
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_228
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9)
}

*/
predicate func_5(Parameter vpng_ptr_167, Variable vlimit_228, EqualityOperation target_9, IfStmt target_5) {
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_228
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_228
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_6(Parameter vpng_ptr_167, Variable vlimit_228, EqualityOperation target_9, IfStmt target_6) {
		target_6.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="push_length"
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_228
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_167
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_7(Function func, UnaryMinusExpr target_7) {
		target_7.getValue()="-1"
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Variable vchunk_name_169, EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vchunk_name_169
		and target_8.getAnOperand().(BitwiseOrExpr).getValue()="1767135348"
}

predicate func_9(Variable vchunk_name_169, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vchunk_name_169
		and target_9.getAnOperand().(BitwiseOrExpr).getValue()="1229209940"
}

predicate func_10(Parameter vpng_ptr_167, Variable vlimit_228, LogicalAndExpr target_10) {
		target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_228
}

from Function func, Parameter vpng_ptr_167, Variable vchunk_name_169, Variable vlimit_228, IfStmt target_5, IfStmt target_6, UnaryMinusExpr target_7, EqualityOperation target_8, EqualityOperation target_9, LogicalAndExpr target_10
where
not func_1(vpng_ptr_167, vchunk_name_169, vlimit_228, target_8, func)
and func_5(vpng_ptr_167, vlimit_228, target_9, target_5)
and func_6(vpng_ptr_167, vlimit_228, target_9, target_6)
and func_7(func, target_7)
and func_8(vchunk_name_169, target_8)
and func_9(vchunk_name_169, target_9)
and func_10(vpng_ptr_167, vlimit_228, target_10)
and vpng_ptr_167.getType().hasName("png_structrp")
and vchunk_name_169.getType().hasName("png_uint_32")
and vlimit_228.getType().hasName("png_alloc_size_t")
and vpng_ptr_167.getParentScope+() = func
and vchunk_name_169.getParentScope+() = func
and vlimit_228.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
