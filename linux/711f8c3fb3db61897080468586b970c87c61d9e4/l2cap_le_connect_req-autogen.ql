/**
 * @name linux-711f8c3fb3db61897080468586b970c87c61d9e4-l2cap_le_connect_req
 * @id cpp/linux/711f8c3fb3db61897080468586b970c87c61d9e4/l2cap-le-connect-req
 * @description linux-711f8c3fb3db61897080468586b970c87c61d9e4-l2cap_le_connect_req CVE-2022-42896
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vchan_5795, Variable vpsm_5797, Variable vresult_5798, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vpsm_5797
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpsm_5797
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_5798
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchan_5795
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0))
}

predicate func_4(Variable vscid_5796, Variable vmtu_5796, Variable vmps_5796, Variable vpsm_5797, Variable v__UNIQUE_ID_ddebug1474_5813) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("__dynamic_pr_debug")
		and target_4.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=v__UNIQUE_ID_ddebug1474_5813
		and target_4.getArgument(1).(StringLiteral).getValue()="psm 0x%2.2x scid 0x%4.4x mtu %u mps %u\n"
		and target_4.getArgument(2).(VariableAccess).getTarget()=vpsm_5797
		and target_4.getArgument(3).(VariableAccess).getTarget()=vscid_5796
		and target_4.getArgument(4).(VariableAccess).getTarget()=vmtu_5796
		and target_4.getArgument(5).(VariableAccess).getTarget()=vmps_5796)
}

from Function func, Variable vchan_5795, Variable vscid_5796, Variable vmtu_5796, Variable vmps_5796, Variable vpsm_5797, Variable vresult_5798, Variable v__UNIQUE_ID_ddebug1474_5813
where
not func_0(vchan_5795, vpsm_5797, vresult_5798, func)
and vchan_5795.getType().hasName("l2cap_chan *")
and vpsm_5797.getType().hasName("__le16")
and func_4(vscid_5796, vmtu_5796, vmps_5796, vpsm_5797, v__UNIQUE_ID_ddebug1474_5813)
and vresult_5798.getType().hasName("u8")
and v__UNIQUE_ID_ddebug1474_5813.getType().hasName("_ddebug")
and vchan_5795.getParentScope+() = func
and vscid_5796.getParentScope+() = func
and vmtu_5796.getParentScope+() = func
and vmps_5796.getParentScope+() = func
and vpsm_5797.getParentScope+() = func
and vresult_5798.getParentScope+() = func
and v__UNIQUE_ID_ddebug1474_5813.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
