/**
 * @name libssh-b166ac4749c78f475b1708f0345e6ca2749c5d6d-ssh_packet_userauth_pk_ok
 * @id cpp/libssh/b166ac4749c78f475b1708f0345e6ca2749c5d6d/ssh-packet-userauth-pk-ok
 * @description libssh-b166ac4749c78f475b1708f0345e6ca2749c5d6d-src/auth.c-ssh_packet_userauth_pk_ok CVE-2018-10933
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_313, Variable v__func__, Parameter vsession_312, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="auth"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_312
		and target_0.getThen() instanceof BlockStmt
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="state"
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="auth"
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_312
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_ssh_log")
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SSH_USERAUTH_PK_OK received in wrong state"
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_313
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getElse().(IfStmt).getElse()=target_0
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrc_313, Variable v__func__, Parameter vsession_312, EqualityOperation target_2, BlockStmt target_1) {
		target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="state"
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="auth"
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_312
		and target_1.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_ssh_log")
		and target_1.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_1.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_1.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assuming SSH_USERAUTH_PK_OK"
		and target_1.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_313
		and target_1.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vsession_312, EqualityOperation target_2) {
		target_2.getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="auth"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_312
}

predicate func_3(Variable vrc_313, Parameter vsession_312, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_313
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ssh_packet_userauth_gssapi_response")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_312
}

predicate func_4(Variable v__func__, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("_ssh_log")
		and target_4.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="keyboard-interactive context, assuming SSH_USERAUTH_INFO_REQUEST"
}

predicate func_5(Variable v__func__, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("_ssh_log")
		and target_5.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assuming SSH_USERAUTH_PK_OK"
}

predicate func_6(Parameter vsession_312, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="state"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="auth"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_312
}

from Function func, Variable vrc_313, Variable v__func__, Parameter vsession_312, BlockStmt target_1, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vrc_313, v__func__, vsession_312, target_2, target_3, target_4, target_5, target_6)
and func_1(vrc_313, v__func__, vsession_312, target_2, target_1)
and func_2(vsession_312, target_2)
and func_3(vrc_313, vsession_312, target_3)
and func_4(v__func__, target_4)
and func_5(v__func__, target_5)
and func_6(vsession_312, target_6)
and vrc_313.getType().hasName("int")
and v__func__.getType() instanceof ArrayType
and vsession_312.getType().hasName("ssh_session")
and vrc_313.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vsession_312.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
