/**
 * @name linux-003b686ace820ce2d635a83f10f2d7f9c147dabc-mwifiex_tm_cmd
 * @id cpp/linux/003b686ace820ce2d635a83f10f2d7f9c147dabc/mwifiex_tm_cmd
 * @description linux-003b686ace820ce2d635a83f10f2d7f9c147dabc-mwifiex_tm_cmd 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vhostcmd_4054, Variable vskb_4056) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhostcmd_4054
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vskb_4056)
}

predicate func_3(Variable vskb_4056) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_3.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_3.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vskb_4056)
}

predicate func_4(Variable verr_4057, Variable vskb_4056) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("kfree_skb")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_4056
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_4057)
}

predicate func_5(Variable verr_4057) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(UnaryMinusExpr).getValue()="-90"
		and target_5.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="90"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_4057)
}

predicate func_7(Variable vhostcmd_4054) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="cmd"
		and target_7.getQualifier().(VariableAccess).getTarget()=vhostcmd_4054)
}

from Function func, Variable verr_4057, Variable vhostcmd_4054, Variable vskb_4056
where
not func_0(vhostcmd_4054, vskb_4056)
and func_3(vskb_4056)
and func_4(verr_4057, vskb_4056)
and func_5(verr_4057)
and verr_4057.getType().hasName("int")
and vhostcmd_4054.getType().hasName("mwifiex_ds_misc_cmd *")
and func_7(vhostcmd_4054)
and vskb_4056.getType().hasName("sk_buff *")
and verr_4057.getParentScope+() = func
and vhostcmd_4054.getParentScope+() = func
and vskb_4056.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
