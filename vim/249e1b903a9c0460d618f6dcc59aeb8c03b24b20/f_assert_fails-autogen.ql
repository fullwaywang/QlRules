/**
 * @name vim-249e1b903a9c0460d618f6dcc59aeb8c03b24b20-f_assert_fails
 * @id cpp/vim/249e1b903a9c0460d618f6dcc59aeb8c03b24b20/f-assert-fails
 * @description vim-249e1b903a9c0460d618f6dcc59aeb8c03b24b20-src/testing.c-f_assert_fails CVE-2022-2817
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vactual_634, NotExpr target_9) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vactual_634
		and target_1.getRValue().(FunctionCall).getTarget().hasName("vim_strsave")
		and target_1.getRValue().(FunctionCall).getArgument(0) instanceof FunctionCall
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vactual_634
		and target_1.getLValue().(VariableAccess).getLocation().isBefore(target_9.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Variable vactual_634, EqualityOperation target_10, NotExpr target_11) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vactual_634
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_11.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char_u *")
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_3))
}

predicate func_4(Variable vtv_646, EqualityOperation target_10, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtv_646
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="li_tv"
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="lv_last"
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mat"
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="lv_u"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_5(Variable vbuf_629, Variable vexpected_630, Variable vtv_646, EqualityOperation target_10, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpected_630
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tv_get_string_buf_chk")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtv_646
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_629
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_6(Variable vexpected_630, Variable vexpected_str_631, Variable verror_found_632, Variable vactual_634, EqualityOperation target_10, IfStmt target_6) {
		target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pattern_match")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpected_630
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vactual_634
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_found_632
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpected_str_631
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vexpected_630
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

/*predicate func_7(Function func, FunctionCall target_7) {
		target_7.getTarget().hasName("get_vim_var_str")
		and target_7.getArgument(0).(Literal).getValue()="3"
		and target_7.getEnclosingFunction() = func
}

*/
predicate func_8(Variable vactual_634, VariableAccess target_8) {
		target_8.getTarget()=vactual_634
		and target_8.getParent().(AssignExpr).getLValue() = target_8
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_vim_var_str")
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="3"
}

predicate func_9(Variable vexpected_630, Variable vactual_634, NotExpr target_9) {
		target_9.getOperand().(FunctionCall).getTarget().hasName("pattern_match")
		and target_9.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpected_630
		and target_9.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vactual_634
		and target_9.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_10(EqualityOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="lv_len"
		and target_10.getAnOperand().(Literal).getValue()="2"
}

predicate func_11(Variable vexpected_630, Variable vactual_634, NotExpr target_11) {
		target_11.getOperand().(FunctionCall).getTarget().hasName("pattern_match")
		and target_11.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpected_630
		and target_11.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vactual_634
		and target_11.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

from Function func, Variable vbuf_629, Variable vexpected_630, Variable vexpected_str_631, Variable verror_found_632, Variable vactual_634, Variable vtv_646, ExprStmt target_4, ExprStmt target_5, IfStmt target_6, VariableAccess target_8, NotExpr target_9, EqualityOperation target_10, NotExpr target_11
where
not func_1(vactual_634, target_9)
and not func_2(vactual_634, target_10, target_11)
and not func_3(func)
and func_4(vtv_646, target_10, target_4)
and func_5(vbuf_629, vexpected_630, vtv_646, target_10, target_5)
and func_6(vexpected_630, vexpected_str_631, verror_found_632, vactual_634, target_10, target_6)
and func_8(vactual_634, target_8)
and func_9(vexpected_630, vactual_634, target_9)
and func_10(target_10)
and func_11(vexpected_630, vactual_634, target_11)
and vbuf_629.getType().hasName("char_u[65]")
and vexpected_630.getType().hasName("char_u *")
and vexpected_str_631.getType().hasName("char_u *")
and verror_found_632.getType().hasName("int")
and vactual_634.getType().hasName("char_u *")
and vtv_646.getType().hasName("typval_T *")
and vbuf_629.getParentScope+() = func
and vexpected_630.getParentScope+() = func
and vexpected_str_631.getParentScope+() = func
and verror_found_632.getParentScope+() = func
and vactual_634.getParentScope+() = func
and vtv_646.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
