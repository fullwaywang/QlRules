/**
 * @name linux-711f8c3fb3db61897080468586b970c87c61d9e4-l2cap_ecred_conn_req
 * @id cpp/linux/711f8c3fb3db61897080468586b970c87c61d9e4/l2cap-ecred-conn-req
 * @description linux-711f8c3fb3db61897080468586b970c87c61d9e4-l2cap_ecred_conn_req CVE-2022-42896
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpsm_5973, Variable vresult_5974, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vpsm_5973
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpsm_5973
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_5974
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_0))
}

predicate func_3(Variable vreq_5966, Variable vpsm_5973) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vpsm_5973
		and target_3.getRValue().(PointerFieldAccess).getTarget().getName()="psm"
		and target_3.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_5966)
}

from Function func, Variable vreq_5966, Variable vpsm_5973, Variable vresult_5974
where
not func_0(vpsm_5973, vresult_5974, func)
and vpsm_5973.getType().hasName("__le16")
and func_3(vreq_5966, vpsm_5973)
and vresult_5974.getType().hasName("u8")
and vreq_5966.getParentScope+() = func
and vpsm_5973.getParentScope+() = func
and vresult_5974.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
