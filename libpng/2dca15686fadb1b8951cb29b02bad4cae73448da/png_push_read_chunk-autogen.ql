/**
 * @name libpng-2dca15686fadb1b8951cb29b02bad4cae73448da-png_push_read_chunk
 * @id cpp/libpng/2dca15686fadb1b8951cb29b02bad4cae73448da/png-push-read-chunk
 * @description libpng-2dca15686fadb1b8951cb29b02bad4cae73448da-pngpread.c-png_push_read_chunk CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_167, ExprStmt target_15, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="width"
		and target_0.getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Parameter vpng_ptr_167, FunctionCall target_1) {
		target_1.getTarget().hasName("png_chunk_error")
		and not target_1.getTarget().hasName("png_check_chunk_length")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vpng_ptr_167
		and target_1.getArgument(1).(StringLiteral).getValue()="chunk data is too large"
}

predicate func_2(Variable vchunk_name_169, BlockStmt target_16, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vchunk_name_169
		and target_2.getAnOperand().(BitwiseOrExpr).getValue()="1229209940"
		and target_2.getParent().(IfStmt).getThen()=target_16
}

predicate func_3(Variable vlimit_173, Parameter vpng_ptr_167, BlockStmt target_17, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="push_length"
		and target_3.getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_3.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vlimit_173
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_17
}

predicate func_4(Variable vlimit_173, Variable vrow_factor_229, Parameter vpng_ptr_167, Function func, IfStmt target_4) {
		target_4.getCondition() instanceof EqualityOperation
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(UnaryMinusExpr).getValue()="-1"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_229
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_229
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="5"
		and target_4.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_4.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_173
		and target_4.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_4.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_173
		and target_4.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and target_4.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_4.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_4.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_4.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_4.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_173
		and target_4.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_4.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_4.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(EqualityOperation target_2, Function func, DeclStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_5.getEnclosingFunction() = func
}

/*predicate func_6(Variable vlimit_173, Variable vrow_factor_229, Parameter vpng_ptr_167, EqualityOperation target_2, IfStmt target_6) {
		target_6.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(UnaryMinusExpr).getValue()="-1"
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_229
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_6.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_6.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_6.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_6.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_229
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

*/
/*predicate func_7(Variable vlimit_173, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_7.getRValue().(Literal).getValue()="2147483647"
}

*/
/*predicate func_8(Variable vlimit_173, EqualityOperation target_2, ExprStmt target_8) {
		target_8.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_8.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_8.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="5"
		and target_8.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit_173
		and target_8.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="32566"
		and target_8.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

*/
/*predicate func_9(Variable vlimit_173, EqualityOperation target_2, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_173
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_173
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

*/
/*predicate func_10(Variable vlimit_173, Parameter vpng_ptr_167, EqualityOperation target_2, IfStmt target_10) {
		target_10.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_173
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

*/
predicate func_11(Variable vlimit_173, Parameter vpng_ptr_167, Function func, IfStmt target_11) {
		target_11.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="push_length"
		and target_11.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_11.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_173
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()=" png_ptr->push_length = %lu, limit = %lu\n"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="push_length"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlimit_173
		and target_11.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

/*predicate func_12(Variable vlimit_173, Parameter vpng_ptr_167, RelationalOperation target_18, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_12.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()=" png_ptr->push_length = %lu, limit = %lu\n"
		and target_12.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="push_length"
		and target_12.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlimit_173
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

*/
/*predicate func_13(RelationalOperation target_18, Function func, ExprStmt target_13) {
		target_13.getExpr().(Literal).getValue()="0"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_13.getEnclosingFunction() = func
}

*/
/*predicate func_14(RelationalOperation target_18, Function func, ExprStmt target_14) {
		target_14.getExpr() instanceof FunctionCall
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_14.getEnclosingFunction() = func
}

*/
predicate func_15(Parameter vpng_ptr_167, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("png_benign_error")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_167
		and target_15.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Too many IDATs found"
}

predicate func_16(BlockStmt target_16) {
		target_16.getStmt(1) instanceof IfStmt
		and target_16.getStmt(2) instanceof ExprStmt
		and target_16.getStmt(3) instanceof ExprStmt
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0) instanceof ExprStmt
		and target_17.getStmt(1) instanceof ExprStmt
		and target_17.getStmt(2) instanceof ExprStmt
}

predicate func_18(Variable vlimit_173, Parameter vpng_ptr_167, RelationalOperation target_18) {
		 (target_18 instanceof GTExpr or target_18 instanceof LTExpr)
		and target_18.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="push_length"
		and target_18.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_18.getLesserOperand().(VariableAccess).getTarget()=vlimit_173
}

from Function func, Variable vchunk_name_169, Variable vlimit_173, Variable vrow_factor_229, Parameter vpng_ptr_167, PointerFieldAccess target_0, FunctionCall target_1, EqualityOperation target_2, PointerFieldAccess target_3, IfStmt target_4, DeclStmt target_5, IfStmt target_11, ExprStmt target_15, BlockStmt target_16, BlockStmt target_17, RelationalOperation target_18
where
func_0(vpng_ptr_167, target_15, target_0)
and func_1(vpng_ptr_167, target_1)
and func_2(vchunk_name_169, target_16, target_2)
and func_3(vlimit_173, vpng_ptr_167, target_17, target_3)
and func_4(vlimit_173, vrow_factor_229, vpng_ptr_167, func, target_4)
and func_5(target_2, func, target_5)
and func_11(vlimit_173, vpng_ptr_167, func, target_11)
and func_15(vpng_ptr_167, target_15)
and func_16(target_16)
and func_17(target_17)
and func_18(vlimit_173, vpng_ptr_167, target_18)
and vchunk_name_169.getType().hasName("png_uint_32")
and vlimit_173.getType().hasName("png_alloc_size_t")
and vrow_factor_229.getType().hasName("size_t")
and vpng_ptr_167.getType().hasName("png_structrp")
and vchunk_name_169.getParentScope+() = func
and vlimit_173.getParentScope+() = func
and vrow_factor_229.getParentScope+() = func
and vpng_ptr_167.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
