/**
 * @name libpng-095b4ce16bb46acb259ea1a4ca6562a623e58d93-png_push_read_chunk
 * @id cpp/libpng/095b4ce16bb46acb259ea1a4ca6562a623e58d93/png-push-read-chunk
 * @description libpng-095b4ce16bb46acb259ea1a4ca6562a623e58d93-pngpread.c-png_push_read_chunk CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_167, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="height"
		and target_0.getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
}

predicate func_1(Variable vlimit_173, Parameter vpng_ptr_167) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("printf")
		and target_1.getArgument(0).(StringLiteral).getValue()=" png_ptr->push_length = %lu, limit = %lu\n"
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="push_length"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_1.getArgument(2).(VariableAccess).getTarget()=vlimit_173)
}

predicate func_2(Variable vlimit_173, RelationalOperation target_14, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483647"
		and target_2.getParent().(IfStmt).getCondition()=target_14
}

predicate func_3(Parameter vpng_ptr_167, RelationalOperation target_15, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_167
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
		and target_3.getParent().(IfStmt).getCondition()=target_15
}

predicate func_4(Variable vlimit_173, VariableAccess target_4) {
		target_4.getTarget()=vlimit_173
}

predicate func_5(EqualityOperation target_16, Function func, DeclStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Variable vlimit_173, Variable vrow_factor_229, Parameter vpng_ptr_167, EqualityOperation target_16, IfStmt target_6) {
		target_6.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(UnaryMinusExpr).getValue()="-1"
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_229
		and target_6.getThen() instanceof ExprStmt
		and target_6.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_6.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_6.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_6.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vrow_factor_229
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_7(Variable vlimit_173, AssignAddExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_7.getRValue().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_7.getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="5"
		and target_7.getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vlimit_173
		and target_7.getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="32566"
}

predicate func_8(Variable vlimit_173, EqualityOperation target_16, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_173
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_173
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_173
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="2147483647"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_14(Parameter vpng_ptr_167, RelationalOperation target_14) {
		 (target_14 instanceof GTExpr or target_14 instanceof LTExpr)
		and target_14.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_14.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_14.getLesserOperand() instanceof DivExpr
}

predicate func_15(Variable vlimit_173, Parameter vpng_ptr_167, RelationalOperation target_15) {
		 (target_15 instanceof GTExpr or target_15 instanceof LTExpr)
		and target_15.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="push_length"
		and target_15.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_15.getLesserOperand().(VariableAccess).getTarget()=vlimit_173
}

predicate func_16(EqualityOperation target_16) {
		target_16.getAnOperand().(BitwiseOrExpr).getValue()="1229209940"
}

from Function func, Variable vlimit_173, Variable vrow_factor_229, Parameter vpng_ptr_167, PointerFieldAccess target_0, ExprStmt target_2, ExprStmt target_3, VariableAccess target_4, DeclStmt target_5, IfStmt target_6, AssignAddExpr target_7, ExprStmt target_8, RelationalOperation target_14, RelationalOperation target_15, EqualityOperation target_16
where
func_0(vpng_ptr_167, target_0)
and not func_1(vlimit_173, vpng_ptr_167)
and func_2(vlimit_173, target_14, target_2)
and func_3(vpng_ptr_167, target_15, target_3)
and func_4(vlimit_173, target_4)
and func_5(target_16, func, target_5)
and func_6(vlimit_173, vrow_factor_229, vpng_ptr_167, target_16, target_6)
and func_7(vlimit_173, target_7)
and func_8(vlimit_173, target_16, target_8)
and func_14(vpng_ptr_167, target_14)
and func_15(vlimit_173, vpng_ptr_167, target_15)
and func_16(target_16)
and vlimit_173.getType().hasName("png_alloc_size_t")
and vrow_factor_229.getType().hasName("size_t")
and vpng_ptr_167.getType().hasName("png_structrp")
and vlimit_173.getParentScope+() = func
and vrow_factor_229.getParentScope+() = func
and vpng_ptr_167.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
