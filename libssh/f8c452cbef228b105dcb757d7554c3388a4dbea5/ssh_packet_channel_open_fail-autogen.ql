/**
 * @name libssh-f8c452cbef228b105dcb757d7554c3388a4dbea5-ssh_packet_channel_open_fail
 * @id cpp/libssh/f8c452cbef228b105dcb757d7554c3388a4dbea5/ssh-packet-channel-open-fail
 * @description libssh-f8c452cbef228b105dcb757d7554c3388a4dbea5-src/channels.c-ssh_packet_channel_open_fail CVE-2018-10933
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vchannel_204, Variable v__func__, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_204
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_ssh_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SSH2_MSG_CHANNEL_OPEN_FAILURE received in incorrect channel state %d"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_204
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="error"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(LabelStmt target_1 |
		target_1.toString() = "label ...:"
		and target_1.getName() ="error"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_1))
}

predicate func_2(Variable v__func__, Parameter vsession_202, ExprStmt target_5, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("_ssh_set_error")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_202
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_2.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Invalid packet"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_2)
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_4(Variable vchannel_204, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vchannel_204
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vchannel_204, Variable v__func__, Parameter vsession_202, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("_ssh_set_error")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_202
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_5.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Channel opening failure: channel %u error (%lu) %s"
		and target_5.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="local_channel"
		and target_5.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_204
}

predicate func_6(Variable v__func__, Parameter vsession_202, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("_ssh_set_error")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_202
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_6.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Invalid packet"
}

from Function func, Variable vchannel_204, Variable v__func__, Parameter vsession_202, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vchannel_204, v__func__, target_4, target_5, target_6, func)
and not func_1(func)
and not func_2(v__func__, vsession_202, target_5, func)
and func_4(vchannel_204, target_4)
and func_5(vchannel_204, v__func__, vsession_202, target_5)
and func_6(v__func__, vsession_202, target_6)
and vchannel_204.getType().hasName("ssh_channel")
and v__func__.getType() instanceof ArrayType
and vsession_202.getType().hasName("ssh_session")
and vchannel_204.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vsession_202.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
