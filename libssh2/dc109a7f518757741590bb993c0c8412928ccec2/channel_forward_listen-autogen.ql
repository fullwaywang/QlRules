/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-channel_forward_listen
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/channel-forward-listen
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/channel.c-channel_forward_listen CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_449, Variable vdata_len_515, BlockStmt target_2, EqualityOperation target_3, AddressOfExpr target_4, LogicalAndExpr target_5) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vrc_449
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdata_len_515
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrc_449, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vrc_449
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unknown"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fwdLstn_state"
		and target_2.getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_3(Variable vrc_449, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vrc_449
		and target_3.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_4(Variable vdata_len_515, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vdata_len_515
}

predicate func_5(Variable vdata_len_515, LogicalAndExpr target_5) {
		target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_len_515
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="5"
}

from Function func, Variable vrc_449, Variable vdata_len_515, VariableAccess target_1, BlockStmt target_2, EqualityOperation target_3, AddressOfExpr target_4, LogicalAndExpr target_5
where
not func_0(vrc_449, vdata_len_515, target_2, target_3, target_4, target_5)
and func_1(vrc_449, target_2, target_1)
and func_2(target_2)
and func_3(vrc_449, target_3)
and func_4(vdata_len_515, target_4)
and func_5(vdata_len_515, target_5)
and vrc_449.getType().hasName("int")
and vdata_len_515.getType().hasName("size_t")
and vrc_449.getParentScope+() = func
and vdata_len_515.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
