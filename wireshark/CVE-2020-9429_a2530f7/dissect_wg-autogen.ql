/**
 * @name wireshark-a2530f740d67d41908e84434bb5ec99480c2ac2e-dissect_wg
 * @id cpp/wireshark/a2530f740d67d41908e84434bb5ec99480c2ac2e/dissect-wg
 * @description wireshark-a2530f740d67d41908e84434bb5ec99480c2ac2e-epan/dissectors/packet-wireguard.c-dissect_wg CVE-2020-9429
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmessage_type_1583, Parameter vtvb_1579, ExprStmt target_1, LogicalAndExpr target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("wg_is_valid_message_length")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmessage_type_1583
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("tvb_reported_length")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_1579
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vmessage_type_1583, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("try_val_to_str")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmessage_type_1583
}

predicate func_2(Variable vmessage_type_1583, Parameter vtvb_1579, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vmessage_type_1583
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("tvb_reported_length")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_1579
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="32"
}

predicate func_3(Variable vmessage_type_1583, Parameter vtvb_1579, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmessage_type_1583
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_guint8")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_1579
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

from Function func, Variable vmessage_type_1583, Parameter vtvb_1579, ExprStmt target_1, LogicalAndExpr target_2, ExprStmt target_3
where
not func_0(vmessage_type_1583, vtvb_1579, target_1, target_2, target_3, func)
and func_1(vmessage_type_1583, target_1)
and func_2(vmessage_type_1583, vtvb_1579, target_2)
and func_3(vmessage_type_1583, vtvb_1579, target_3)
and vmessage_type_1583.getType().hasName("guint32")
and vtvb_1579.getType().hasName("tvbuff_t *")
and vmessage_type_1583.getParentScope+() = func
and vtvb_1579.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
