/**
 * @name linux-f94b47c6bde624d6c07f43054087607c52054a95-_rtw_init_xmit_priv
 * @id cpp/linux/f94b47c6bde624d6c07f43054087607c52054a95/-rtw-init-xmit-priv
 * @description linux-f94b47c6bde624d6c07f43054087607c52054a95-_rtw_init_xmit_priv 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpadapter_40, Variable vres_45) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vres_45
		and target_0.getRValue().(FunctionCall).getTarget().hasName("rtw_alloc_hwxmits")
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpadapter_40)
}

predicate func_1(Variable vres_45, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vres_45
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_45
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(38)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(38).getFollowingStmt()=target_1))
}

predicate func_5(Parameter vpadapter_40) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("rtw_alloc_hwxmits")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vpadapter_40)
}

predicate func_6(Variable vres_45, Function func) {
	exists(ReturnStmt target_6 |
		target_6.getExpr().(VariableAccess).getTarget()=vres_45
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

from Function func, Parameter vpadapter_40, Variable vres_45
where
not func_0(vpadapter_40, vres_45)
and not func_1(vres_45, func)
and func_5(vpadapter_40)
and vpadapter_40.getType().hasName("adapter *")
and vres_45.getType().hasName("int")
and func_6(vres_45, func)
and vpadapter_40.getParentScope+() = func
and vres_45.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
