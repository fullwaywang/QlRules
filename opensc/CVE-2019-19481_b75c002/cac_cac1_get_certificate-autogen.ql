/**
 * @name opensc-b75c002cfb1fd61cd20ec938ff4937d7b1a94278-cac_cac1_get_certificate
 * @id cpp/opensc/b75c002cfb1fd61cd20ec938ff4937d7b1a94278/cac-cac1-get-certificate
 * @description opensc-b75c002cfb1fd61cd20ec938ff4937d7b1a94278-src/libopensc/card-cac1.c-cac_cac1_get_certificate CVE-2019-19481
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vleft_71, Variable vnext_len_72, ExprStmt target_8, VariableAccess target_0) {
		target_0.getTarget()=vnext_len_72
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vleft_71
		and target_0.getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="100"
		and target_0.getParent().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vleft_71
		and target_0.getParent().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="100"
		and target_8.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
}

predicate func_1(Variable vleft_71, Variable vnext_len_72, ExprStmt target_10, VariableAccess target_1) {
		target_1.getTarget()=vnext_len_72
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vleft_71
		and target_1.getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="sw2"
		and target_1.getParent().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vleft_71
		and target_1.getParent().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ValueFieldAccess).getTarget().getName()="sw2"
		and target_10.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr() instanceof AssignPointerAddExpr
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vleft_71, Variable vlen_72, AssignSubExpr target_3) {
		target_3.getLValue().(VariableAccess).getTarget()=vleft_71
		and target_3.getRValue().(VariableAccess).getTarget()=vlen_72
}

predicate func_4(Variable vout_ptr_69, Variable vlen_72, AssignPointerAddExpr target_4) {
		target_4.getLValue().(VariableAccess).getTarget()=vout_ptr_69
		and target_4.getRValue().(VariableAccess).getTarget()=vlen_72
}

predicate func_6(Function func, CommaExpr target_6) {
		target_6.getLeftOperand() instanceof AssignSubExpr
		and target_6.getRightOperand() instanceof AssignPointerAddExpr
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vlen_72, Variable vnext_len_72, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vlen_72
		and target_7.getRValue().(VariableAccess).getTarget()=vnext_len_72
}

predicate func_8(Variable vleft_71, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vleft_71
		and target_8.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="4096"
}

predicate func_10(Variable vleft_71, Variable vlen_72, ExprStmt target_10) {
		target_10.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vleft_71
		and target_10.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vlen_72
}

from Function func, Variable vout_ptr_69, Variable vleft_71, Variable vlen_72, Variable vnext_len_72, VariableAccess target_0, VariableAccess target_1, AssignSubExpr target_3, AssignPointerAddExpr target_4, CommaExpr target_6, AssignExpr target_7, ExprStmt target_8, ExprStmt target_10
where
func_0(vleft_71, vnext_len_72, target_8, target_0)
and func_1(vleft_71, vnext_len_72, target_10, target_1)
and not func_2(func)
and func_3(vleft_71, vlen_72, target_3)
and func_4(vout_ptr_69, vlen_72, target_4)
and func_6(func, target_6)
and func_7(vlen_72, vnext_len_72, target_7)
and func_8(vleft_71, target_8)
and func_10(vleft_71, vlen_72, target_10)
and vout_ptr_69.getType().hasName("u8 *")
and vleft_71.getType().hasName("size_t")
and vlen_72.getType().hasName("size_t")
and vnext_len_72.getType().hasName("size_t")
and vout_ptr_69.getParentScope+() = func
and vleft_71.getParentScope+() = func
and vlen_72.getParentScope+() = func
and vnext_len_72.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
