/**
 * @name c-ares-1cc7e83c3bdfaafbc5919c95025592d8de3a170e-host_callback
 * @id cpp/c-ares/1cc7e83c3bdfaafbc5919c95025592d8de3a170e/host-callback
 * @description c-ares-1cc7e83c3bdfaafbc5919c95025592d8de3a170e-ares_getaddrinfo.c-host_callback CVE-2020-14354
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstatus_536, Variable vhquery_539, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("end_hquery")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhquery_539
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstatus_536
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_3, Function func) {
	exists(ReturnStmt target_1 |
		target_1.toString() = "return ..."
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vstatus_536, Variable vhquery_539, EqualityOperation target_6, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("end_hquery")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhquery_539
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstatus_536
		and target_2.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_3(Parameter vstatus_536, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vstatus_536
		and target_3.getAnOperand().(Literal).getValue()="16"
}

predicate func_4(Parameter vstatus_536, Variable vhquery_539, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("end_hquery")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhquery_539
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstatus_536
}

predicate func_5(Variable vhquery_539, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ares__parse_into_addrinfo")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="ai"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhquery_539
}

predicate func_6(Parameter vstatus_536, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vstatus_536
		and target_6.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vstatus_536, Variable vhquery_539, BlockStmt target_2, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, EqualityOperation target_6
where
not func_0(vstatus_536, vhquery_539, target_3, target_4, target_5)
and not func_1(target_3, func)
and func_2(vstatus_536, vhquery_539, target_6, target_2)
and func_3(vstatus_536, target_3)
and func_4(vstatus_536, vhquery_539, target_4)
and func_5(vhquery_539, target_5)
and func_6(vstatus_536, target_6)
and vstatus_536.getType().hasName("int")
and vhquery_539.getType().hasName("host_query *")
and vstatus_536.getParentScope+() = func
and vhquery_539.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
