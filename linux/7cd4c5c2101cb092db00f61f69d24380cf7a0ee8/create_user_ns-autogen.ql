/**
 * @name linux-7cd4c5c2101cb092db00f61f69d24380cf7a0ee8-create_user_ns
 * @id cpp/linux/7cd4c5c2101cb092db00f61f69d24380cf7a0ee8/create_user_ns
 * @description linux-7cd4c5c2101cb092db00f61f69d24380cf7a0ee8-create_user_ns CVE-2022-0492
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vret_87, Parameter vnew_81, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_87
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("security_create_user_ns")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew_81
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0))
}

predicate func_1(Variable vret_87, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_87
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vnew_81) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="egid"
		and target_2.getQualifier().(VariableAccess).getTarget()=vnew_81)
}

from Function func, Variable vret_87, Parameter vnew_81
where
not func_0(vret_87, vnew_81, func)
and not func_1(vret_87, func)
and vret_87.getType().hasName("int")
and vnew_81.getType().hasName("cred *")
and func_2(vnew_81)
and vret_87.getParentScope+() = func
and vnew_81.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
