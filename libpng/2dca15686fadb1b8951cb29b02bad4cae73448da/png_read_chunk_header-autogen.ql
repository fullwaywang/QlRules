/**
 * @name libpng-2dca15686fadb1b8951cb29b02bad4cae73448da-png_read_chunk_header
 * @id cpp/libpng/2dca15686fadb1b8951cb29b02bad4cae73448da/png-read-chunk-header
 * @description libpng-2dca15686fadb1b8951cb29b02bad4cae73448da-pngrutil.c-png_read_chunk_header CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_156, FunctionCall target_0) {
		target_0.getTarget().hasName("png_chunk_error")
		and not target_0.getTarget().hasName("png_check_chunk_length")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
		and target_0.getArgument(1).(StringLiteral).getValue()="chunk data is too large"
}

predicate func_1(Parameter vpng_ptr_156, BlockStmt target_14, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="chunk_name"
		and target_1.getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_1.getParent().(NEExpr).getAnOperand() instanceof BitwiseOrExpr
		and target_1.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_14
}

predicate func_2(Variable vlength_159, Variable vlimit_160, BlockStmt target_15, VariableAccess target_2) {
		target_2.getTarget()=vlength_159
		and target_2.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vlimit_160
		and target_2.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_15
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vlimit_160, Variable vrow_factor_199, Parameter vpng_ptr_156, Function func, IfStmt target_4) {
		target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="chunk_name"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_4.getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="1229209940"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_160
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_4.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_4.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(UnaryMinusExpr).getValue()="-1"
		and target_4.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_199
		and target_4.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_4.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_4.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_4.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_199
		and target_4.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_4.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_4.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="5"
		and target_4.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_4.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_160
		and target_4.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_4.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_160
		and target_4.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

/*predicate func_5(Variable vlimit_160, Parameter vpng_ptr_156, EqualityOperation target_16, IfStmt target_5) {
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_160
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
predicate func_6(EqualityOperation target_16, Function func, DeclStmt target_6) {
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_6.getEnclosingFunction() = func
}

/*predicate func_7(Variable vlimit_160, Variable vrow_factor_199, Parameter vpng_ptr_156, EqualityOperation target_16, IfStmt target_7) {
		target_7.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(UnaryMinusExpr).getValue()="-1"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_199
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_7.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_7.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_7.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_7.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_199
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
/*predicate func_8(Variable vlimit_160, AssignExpr target_8) {
		target_8.getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_8.getRValue().(Literal).getValue()="2147483647"
}

*/
/*predicate func_9(Variable vlimit_160, EqualityOperation target_16, ExprStmt target_9) {
		target_9.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_9.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_9.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="5"
		and target_9.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit_160
		and target_9.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="32566"
		and target_9.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
/*predicate func_10(Variable vlimit_160, EqualityOperation target_16, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_160
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_160
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_160
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
predicate func_11(Variable vlength_159, Variable vlimit_160, Function func, IfStmt target_11) {
		target_11.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_159
		and target_11.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_160
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

/*predicate func_12(RelationalOperation target_17, Function func, ExprStmt target_12) {
		target_12.getExpr().(Literal).getValue()="0"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_12.getEnclosingFunction() = func
}

*/
/*predicate func_13(RelationalOperation target_17, Function func, ExprStmt target_13) {
		target_13.getExpr() instanceof FunctionCall
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_13.getEnclosingFunction() = func
}

*/
predicate func_14(BlockStmt target_14) {
		target_14.getStmt(0) instanceof IfStmt
}

predicate func_15(BlockStmt target_15) {
		target_15.getStmt(0) instanceof ExprStmt
		and target_15.getStmt(1) instanceof ExprStmt
}

predicate func_16(Parameter vpng_ptr_156, EqualityOperation target_16) {
		target_16.getAnOperand().(PointerFieldAccess).getTarget().getName()="chunk_name"
		and target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_16.getAnOperand() instanceof BitwiseOrExpr
}

predicate func_17(Variable vlength_159, Variable vlimit_160, RelationalOperation target_17) {
		 (target_17 instanceof GTExpr or target_17 instanceof LTExpr)
		and target_17.getGreaterOperand().(VariableAccess).getTarget()=vlength_159
		and target_17.getLesserOperand().(VariableAccess).getTarget()=vlimit_160
}

from Function func, Variable vlength_159, Variable vlimit_160, Variable vrow_factor_199, Parameter vpng_ptr_156, FunctionCall target_0, PointerFieldAccess target_1, VariableAccess target_2, DeclStmt target_3, IfStmt target_4, DeclStmt target_6, IfStmt target_11, BlockStmt target_14, BlockStmt target_15, EqualityOperation target_16, RelationalOperation target_17
where
func_0(vpng_ptr_156, target_0)
and func_1(vpng_ptr_156, target_14, target_1)
and func_2(vlength_159, vlimit_160, target_15, target_2)
and func_3(func, target_3)
and func_4(vlimit_160, vrow_factor_199, vpng_ptr_156, func, target_4)
and func_6(target_16, func, target_6)
and func_11(vlength_159, vlimit_160, func, target_11)
and func_14(target_14)
and func_15(target_15)
and func_16(vpng_ptr_156, target_16)
and func_17(vlength_159, vlimit_160, target_17)
and vlength_159.getType().hasName("png_uint_32")
and vlimit_160.getType().hasName("png_alloc_size_t")
and vrow_factor_199.getType().hasName("size_t")
and vpng_ptr_156.getType().hasName("png_structrp")
and vlength_159.getParentScope+() = func
and vlimit_160.getParentScope+() = func
and vrow_factor_199.getParentScope+() = func
and vpng_ptr_156.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
