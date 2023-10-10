/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-diffie_hellman_sha256
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/diffie-hellman-sha256
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/kex.c-diffie_hellman_sha256 CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexchange_state_791, Variable vret_793, Parameter vsession_783, EqualityOperation target_2, AddressOfExpr target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="s_packet_len"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexchange_state_791
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_793
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_783
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected packet length"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="clean_exit"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vexchange_state_791, Variable vret_793, Parameter vsession_783, EqualityOperation target_2, ExprStmt target_7, ExprStmt target_8, ExprStmt target_6, IfStmt target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="server_hostkey_len"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_783
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="s_packet_len"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexchange_state_791
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="5"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_793
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_783
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-41"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Host key length out of bounds"
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="clean_exit"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_7.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vexchange_state_791, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexchange_state_791
}

predicate func_3(Parameter vexchange_state_791, AddressOfExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="req_state"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexchange_state_791
}

predicate func_4(Parameter vexchange_state_791, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="s"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexchange_state_791
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="s_packet"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexchange_state_791
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vret_793, Parameter vsession_783, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_793
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_783
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-9"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Timed out waiting for KEX reply"
}

predicate func_6(Parameter vexchange_state_791, Parameter vsession_783, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="server_hostkey_len"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_783
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="s"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexchange_state_791
}

predicate func_7(Parameter vexchange_state_791, ExprStmt target_7) {
		target_7.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="s"
		and target_7.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexchange_state_791
		and target_7.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="4"
}

predicate func_8(Parameter vexchange_state_791, Parameter vsession_783, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="server_hostkey"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_783
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="s"
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexchange_state_791
		and target_8.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="server_hostkey_len"
		and target_8.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_783
}

predicate func_9(Parameter vsession_783, IfStmt target_9) {
		target_9.getCondition().(PointerFieldAccess).getTarget().getName()="server_hostkey"
		and target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_783
		and target_9.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_9.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_783
		and target_9.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="server_hostkey"
		and target_9.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_783
		and target_9.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_9.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_783
}

from Function func, Parameter vexchange_state_791, Variable vret_793, Parameter vsession_783, EqualityOperation target_2, AddressOfExpr target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, IfStmt target_9
where
not func_0(vexchange_state_791, vret_793, vsession_783, target_2, target_3, target_4, target_5, target_6)
and not func_1(vexchange_state_791, vret_793, vsession_783, target_2, target_7, target_8, target_6, target_9)
and func_2(vexchange_state_791, target_2)
and func_3(vexchange_state_791, target_3)
and func_4(vexchange_state_791, target_4)
and func_5(vret_793, vsession_783, target_5)
and func_6(vexchange_state_791, vsession_783, target_6)
and func_7(vexchange_state_791, target_7)
and func_8(vexchange_state_791, vsession_783, target_8)
and func_9(vsession_783, target_9)
and vexchange_state_791.getType().hasName("kmdhgGPshakex_state_t *")
and vret_793.getType().hasName("int")
and vsession_783.getType().hasName("LIBSSH2_SESSION *")
and vexchange_state_791.getParentScope+() = func
and vret_793.getParentScope+() = func
and vsession_783.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
