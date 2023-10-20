/**
 * @name vim-338f1fc0ee3ca929387448fe464579d6113fa76a-nv_gotofile
 * @id cpp/vim/338f1fc0ee3ca929387448fe464579d6113fa76a/nv-gotofile
 * @description vim-338f1fc0ee3ca929387448fe464579d6113fa76a-src/normal.c-nv_gotofile CVE-2022-1897
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("text_locked")
		and not target_0.getTarget().hasName("check_text_locked")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vcap_4047, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="oap"
		and target_1.getQualifier().(VariableAccess).getTarget()=vcap_4047
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_2(FunctionCall target_0, Function func, ReturnStmt target_2) {
		target_2.toString() = "return ..."
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_0
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vcap_4047, FunctionCall target_0, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("clearopbeep")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oap"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_4047
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_0
}

predicate func_4(FunctionCall target_0, Function func, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("text_locked_msg")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_0
		and target_4.getEnclosingFunction() = func
}

from Function func, Parameter vcap_4047, FunctionCall target_0, PointerFieldAccess target_1, ReturnStmt target_2, ExprStmt target_3, ExprStmt target_4
where
func_0(func, target_0)
and func_1(vcap_4047, target_1)
and func_2(target_0, func, target_2)
and func_3(vcap_4047, target_0, target_3)
and func_4(target_0, func, target_4)
and vcap_4047.getType().hasName("cmdarg_T *")
and vcap_4047.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
