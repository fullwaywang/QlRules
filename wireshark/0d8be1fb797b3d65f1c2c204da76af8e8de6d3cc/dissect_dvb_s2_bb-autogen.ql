/**
 * @name wireshark-0d8be1fb797b3d65f1c2c204da76af8e8de6d3cc-dissect_dvb_s2_bb
 * @id cpp/wireshark/0d8be1fb797b3d65f1c2c204da76af8e8de6d3cc/dissect-dvb-s2-bb
 * @description wireshark-0d8be1fb797b3d65f1c2c204da76af8e8de6d3cc-epan/dissectors/packet-dvb-s2-bb.c-dissect_dvb_s2_bb CVE-2021-22222
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbb_data_len_1148, LogicalAndExpr target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbb_data_len_1148
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

predicate func_1(Variable vbb_data_len_1148, LogicalAndExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbb_data_len_1148
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
}

predicate func_2(Variable vbb_data_len_1148, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbb_data_len_1148
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Variable vbb_data_len_1148, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbb_data_len_1148
		and target_3.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

from Function func, Variable vbb_data_len_1148, LogicalAndExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vbb_data_len_1148, target_1, target_2, target_3)
and func_1(vbb_data_len_1148, target_1)
and func_2(vbb_data_len_1148, target_2)
and func_3(vbb_data_len_1148, target_3)
and vbb_data_len_1148.getType().hasName("guint16")
and vbb_data_len_1148.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
