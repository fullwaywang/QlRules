/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-_libssh2_packet_add
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/-libssh2-packet-add
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/packet.c-_libssh2_packet_add CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnamelen_820, Variable vchannelp_426, VariableAccess target_2, AddExpr target_3, IfStmt target_4, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnamelen_820
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="4294967294"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_426
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation())
		and target_4.getCondition().(VariableAccess).getLocation().isBefore(target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vnamelen_820, Variable vchannelp_426, Parameter vsession_418, VariableAccess target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_426
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_418
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnamelen_820
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_418
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vchannelp_426, VariableAccess target_2) {
		target_2.getTarget()=vchannelp_426
}

predicate func_3(Variable vnamelen_820, AddExpr target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vnamelen_820
		and target_3.getAnOperand().(Literal).getValue()="1"
}

predicate func_4(Variable vnamelen_820, Variable vchannelp_426, Parameter vsession_418, IfStmt target_4) {
		target_4.getCondition().(VariableAccess).getTarget()=vchannelp_426
		and target_4.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannelp_426
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_418
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="memory for signal name"
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="exit_signal"
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnamelen_820
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
}

from Function func, Variable vnamelen_820, Variable vchannelp_426, Parameter vsession_418, ExprStmt target_1, VariableAccess target_2, AddExpr target_3, IfStmt target_4
where
not func_0(vnamelen_820, vchannelp_426, target_2, target_3, target_4, target_1)
and func_1(vnamelen_820, vchannelp_426, vsession_418, target_2, target_1)
and func_2(vchannelp_426, target_2)
and func_3(vnamelen_820, target_3)
and func_4(vnamelen_820, vchannelp_426, vsession_418, target_4)
and vnamelen_820.getType().hasName("uint32_t")
and vchannelp_426.getType().hasName("LIBSSH2_CHANNEL *")
and vsession_418.getType().hasName("LIBSSH2_SESSION *")
and vnamelen_820.getParentScope+() = func
and vchannelp_426.getParentScope+() = func
and vsession_418.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
