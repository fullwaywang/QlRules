/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-channel_request_pty
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/channel-request-pty
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/channel.c-channel_request_pty CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_912, Variable vdata_len_972, BlockStmt target_2, ReturnStmt target_3, AddressOfExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vrc_912
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdata_len_972
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrc_912, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vrc_912
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="reqPTY_state"
		and target_2.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_2.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed to require the PTY package"
}

predicate func_3(Variable vrc_912, ReturnStmt target_3) {
		target_3.getExpr().(VariableAccess).getTarget()=vrc_912
}

predicate func_4(Variable vdata_len_972, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vdata_len_972
}

from Function func, Variable vrc_912, Variable vdata_len_972, VariableAccess target_1, BlockStmt target_2, ReturnStmt target_3, AddressOfExpr target_4
where
not func_0(vrc_912, vdata_len_972, target_2, target_3, target_4)
and func_1(vrc_912, target_2, target_1)
and func_2(target_2)
and func_3(vrc_912, target_3)
and func_4(vdata_len_972, target_4)
and vrc_912.getType().hasName("int")
and vdata_len_972.getType().hasName("size_t")
and vrc_912.getParentScope+() = func
and vdata_len_972.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
