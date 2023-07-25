/**
 * @name libpng-2dbef2f2a9e759a80d2decb6862518acf4919c59-png_read_chunk_header
 * @id cpp/libpng/2dbef2f2a9e759a80d2decb6862518acf4919c59/png-read-chunk-header
 * @description libpng-2dbef2f2a9e759a80d2decb6862518acf4919c59-pngrutil.c-png_read_chunk_header CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_156, BlockStmt target_8) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_0.getLesserOperand().(DivExpr).getLeftOperand().(UnaryMinusExpr).getValue()="-1"
		and target_0.getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getParent().(IfStmt).getThen()=target_8)
}

predicate func_1(Parameter vpng_ptr_156, Variable vlimit_160, RelationalOperation target_6, ExprStmt target_9) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_1.getParent().(IfStmt).getCondition()=target_6
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vlimit_160, EqualityOperation target_10, ExprStmt target_7) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="5"
		and target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit_160
		and target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="32566"
		and target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_3(Variable vlimit_160, EqualityOperation target_10, RelationalOperation target_6) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_160
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_160
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vpng_ptr_156, Variable vlength_159, Variable vlimit_160, ExprStmt target_11, RelationalOperation target_6, ReturnStmt target_12, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof RelationalOperation
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()=" length = %lu, limit = %lu\n"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_159
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlimit_160
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_4)
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_12.getExpr().(VariableAccess).getLocation()))
}

/*predicate func_5(Variable vlength_159, Variable vlimit_160, RelationalOperation target_6, ReturnStmt target_12) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_5.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()=" length = %lu, limit = %lu\n"
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_159
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlimit_160
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_12.getExpr().(VariableAccess).getLocation()))
}

*/
predicate func_6(Variable vlength_159, Variable vlimit_160, BlockStmt target_8, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vlength_159
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vlimit_160
		and target_6.getParent().(IfStmt).getThen()=target_8
}

predicate func_7(Variable vlimit_160, EqualityOperation target_10, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_8(Parameter vpng_ptr_156, BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
}

predicate func_9(Parameter vpng_ptr_156, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
		and target_9.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
}

predicate func_10(Parameter vpng_ptr_156, EqualityOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="chunk_name"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_10.getAnOperand().(BitwiseOrExpr).getValue()="1229209940"
}

predicate func_11(Parameter vpng_ptr_156, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="io_state"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_11.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="65"
}

predicate func_12(Variable vlength_159, ReturnStmt target_12) {
		target_12.getExpr().(VariableAccess).getTarget()=vlength_159
}

from Function func, Parameter vpng_ptr_156, Variable vlength_159, Variable vlimit_160, RelationalOperation target_6, ExprStmt target_7, BlockStmt target_8, ExprStmt target_9, EqualityOperation target_10, ExprStmt target_11, ReturnStmt target_12
where
not func_0(vpng_ptr_156, target_8)
and not func_1(vpng_ptr_156, vlimit_160, target_6, target_9)
and not func_2(vlimit_160, target_10, target_7)
and not func_3(vlimit_160, target_10, target_6)
and not func_4(vpng_ptr_156, vlength_159, vlimit_160, target_11, target_6, target_12, func)
and func_6(vlength_159, vlimit_160, target_8, target_6)
and func_7(vlimit_160, target_10, target_7)
and func_8(vpng_ptr_156, target_8)
and func_9(vpng_ptr_156, target_9)
and func_10(vpng_ptr_156, target_10)
and func_11(vpng_ptr_156, target_11)
and func_12(vlength_159, target_12)
and vpng_ptr_156.getType().hasName("png_structrp")
and vlength_159.getType().hasName("png_uint_32")
and vlimit_160.getType().hasName("png_alloc_size_t")
and vpng_ptr_156.getParentScope+() = func
and vlength_159.getParentScope+() = func
and vlimit_160.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
